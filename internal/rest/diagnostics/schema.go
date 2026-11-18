// Copyright (C) 2026 Christian Rößner
//
// SPDX-License-Identifier: AGPL-3.0-only
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, version 3 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package diagnostics

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"

	"github.com/croessner/nauthilus-director/internal/rest/generated"
	"github.com/getkin/kin-openapi/openapi3"
)

const (
	componentSchemaPrefix = "#/components/schemas/"

	// maxSchemaDepth bounds $ref inlining.
	maxSchemaDepth = 16

	contentTypeJSON = "application/json"

	keywordRef                  = "$ref"
	schemaTypeObject            = "object"
	keywordProperties           = "properties"
	keywordAdditionalProperties = "additionalProperties"
)

// argumentSchema is the resolved tool input contract of one operation.
type argumentSchema struct {
	schema   json.RawMessage
	required []string
	method   string
}

var (
	schemaOnce   sync.Once
	schemaCache  map[string]argumentSchema
	schemaFailed error
)

// InputSchema returns the operation's arguments as a self-contained JSON Schema object. It is
// derived from the embedded control API OpenAPI document: path and query parameters become
// properties, or the JSON request body is used as is, with every $ref inlined and OpenAPI-only
// keywords translated. The REST contract and the tool schema therefore come from one source.
func (o Operation) InputSchema() (json.RawMessage, error) {
	resolved, err := o.argumentSchema()
	if err != nil {
		return nil, err
	}

	return append(json.RawMessage(nil), resolved.schema...), nil
}

// argumentSchema returns the cached argument contract of the operation.
func (o Operation) argumentSchema() (argumentSchema, error) {
	schemaOnce.Do(loadArgumentSchemas)

	if schemaFailed != nil {
		return argumentSchema{}, schemaFailed
	}

	resolved, ok := schemaCache[o.Name]
	if !ok {
		return argumentSchema{}, fmt.Errorf("no input schema for %s", o.Name)
	}

	return resolved, nil
}

// loadArgumentSchemas resolves every operation's argument schema once.
func loadArgumentSchemas() {
	document, err := generated.GetSpec()
	if err != nil {
		schemaFailed = fmt.Errorf("load embedded control API document: %w", err)

		return
	}

	components, err := componentSchemas(document)
	if err != nil {
		schemaFailed = err

		return
	}

	index := operationIndex(document)
	schemaCache = make(map[string]argumentSchema, len(operations))

	for _, operation := range operations {
		located, ok := index[strings.ToLower(operation.OperationID)]
		if !ok {
			schemaFailed = fmt.Errorf("%s: operation %s is not in the control API document", operation.Name, operation.OperationID)

			return
		}

		resolved, buildErr := buildArgumentSchema(components, located, operation.hiddenParameters)
		if buildErr != nil {
			schemaFailed = fmt.Errorf("%s: %w", operation.Name, buildErr)

			return
		}

		schemaCache[operation.Name] = resolved
	}
}

// locatedOperation is one OpenAPI operation with its HTTP method and path-level parameters.
type locatedOperation struct {
	operation  *openapi3.Operation
	pathParams openapi3.Parameters
	method     string
}

// operationIndex maps every operationId of the document to its operation. Keys are lower-cased
// because the embedded document carries the generator-normalized identifiers.
func operationIndex(document *openapi3.T) map[string]locatedOperation {
	index := map[string]locatedOperation{}

	if document.Paths == nil {
		return index
	}

	for _, item := range document.Paths.Map() {
		for method, operation := range item.Operations() {
			if operation != nil && operation.OperationID != "" {
				index[strings.ToLower(operation.OperationID)] = locatedOperation{operation: operation, pathParams: item.Parameters, method: method}
			}
		}
	}

	return index
}

// componentSchemas renders the component schemas as generic JSON values for $ref inlining.
func componentSchemas(document *openapi3.T) (map[string]any, error) {
	if document.Components == nil {
		return map[string]any{}, nil
	}

	raw, err := json.Marshal(document.Components.Schemas)
	if err != nil {
		return nil, fmt.Errorf("render component schemas: %w", err)
	}

	components := map[string]any{}
	if err = json.Unmarshal(raw, &components); err != nil {
		return nil, fmt.Errorf("decode component schemas: %w", err)
	}

	return components, nil
}

// buildArgumentSchema builds the object schema of one operation from its parameters or its body.
func buildArgumentSchema(components map[string]any, located locatedOperation, hidden []string) (argumentSchema, error) {
	parameters := mergedParameters(located.pathParams, located.operation.Parameters)
	body := located.operation.RequestBody

	exposed := slices.DeleteFunc(parameters, func(parameter *openapi3.Parameter) bool {
		return slices.Contains(hidden, parameter.Name)
	})

	if body != nil && len(exposed) > 0 {
		return argumentSchema{}, errors.New("operations with both parameters and a request body are not supported")
	}

	if body != nil {
		return bodySchema(components, body, located.method)
	}

	return parameterSchema(components, exposed, located.method)
}

// mergedParameters returns path-level parameters overridden by operation parameters of the same
// name and location, in a stable order.
func mergedParameters(pathParams openapi3.Parameters, operationParams openapi3.Parameters) []*openapi3.Parameter {
	merged := make([]*openapi3.Parameter, 0, len(pathParams)+len(operationParams))

	for _, list := range []openapi3.Parameters{pathParams, operationParams} {
		for _, ref := range list {
			if ref == nil || ref.Value == nil {
				continue
			}

			merged = slices.DeleteFunc(merged, func(existing *openapi3.Parameter) bool {
				return existing.Name == ref.Value.Name && existing.In == ref.Value.In
			})
			merged = append(merged, ref.Value)
		}
	}

	return merged
}

// parameterSchema renders path and query parameters as the properties of one object.
func parameterSchema(components map[string]any, parameters []*openapi3.Parameter, method string) (argumentSchema, error) {
	properties := map[string]any{}
	required := []string{}

	for _, parameter := range parameters {
		if parameter.In != openapi3.ParameterInPath && parameter.In != openapi3.ParameterInQuery {
			return argumentSchema{}, fmt.Errorf("parameter %s in %s is not supported", parameter.Name, parameter.In)
		}

		property, err := renderSchemaRef(components, parameter.Schema)
		if err != nil {
			return argumentSchema{}, fmt.Errorf("parameter %s: %w", parameter.Name, err)
		}

		if parameter.Description != "" {
			if _, described := property["description"]; !described {
				property["description"] = parameter.Description
			}
		}

		properties[parameter.Name] = property

		if parameter.Required || parameter.In == openapi3.ParameterInPath {
			required = append(required, parameter.Name)
		}
	}

	slices.Sort(required)

	object := map[string]any{"type": schemaTypeObject, keywordProperties: properties, keywordAdditionalProperties: false}
	if len(required) > 0 {
		object["required"] = required
	}

	return renderArgumentSchema(object, required, method)
}

// bodySchema renders the JSON request body schema as the tool argument object.
func bodySchema(components map[string]any, body *openapi3.RequestBodyRef, method string) (argumentSchema, error) {
	if body.Value == nil {
		return argumentSchema{}, errors.New("request body is unresolved")
	}

	media := body.Value.Content.Get(contentTypeJSON)
	if media == nil {
		return argumentSchema{}, errors.New("request body has no application/json schema")
	}

	object, err := renderSchemaRef(components, media.Schema)
	if err != nil {
		return argumentSchema{}, err
	}

	if object["type"] != schemaTypeObject {
		return argumentSchema{}, errors.New("request body schema is not an object")
	}

	if _, set := object[keywordAdditionalProperties]; !set {
		object[keywordAdditionalProperties] = false
	}

	var required []string

	if list, ok := object["required"].([]any); ok {
		for _, name := range list {
			if text, isText := name.(string); isText {
				required = append(required, text)
			}
		}
	}

	return renderArgumentSchema(object, required, method)
}

// renderArgumentSchema marshals the final object schema.
func renderArgumentSchema(object map[string]any, required []string, method string) (argumentSchema, error) {
	rendered, err := json.Marshal(object)
	if err != nil {
		return argumentSchema{}, err
	}

	return argumentSchema{schema: rendered, required: required, method: method}, nil
}

// renderSchemaRef renders one schema reference as a self-contained JSON Schema object.
func renderSchemaRef(components map[string]any, ref *openapi3.SchemaRef) (map[string]any, error) {
	if ref == nil {
		return nil, errors.New("missing schema")
	}

	var node any = map[string]any{keywordRef: ref.Ref}

	if ref.Ref == "" {
		raw, err := json.Marshal(ref.Value)
		if err != nil {
			return nil, err
		}

		if err = json.Unmarshal(raw, &node); err != nil {
			return nil, err
		}
	}

	inlined, err := inlineSchema(components, node, 0)
	if err != nil {
		return nil, err
	}

	object, ok := inlined.(map[string]any)
	if !ok {
		return nil, errors.New("schema is not an object")
	}

	return object, nil
}

// inlineSchema copies a schema node, replacing component references by their definitions and
// translating OpenAPI 3.0 keywords into JSON Schema 2020-12.
func inlineSchema(components map[string]any, node any, depth int) (any, error) {
	if depth > maxSchemaDepth {
		return nil, fmt.Errorf("schema references nest deeper than %d", maxSchemaDepth)
	}

	switch typed := node.(type) {
	case map[string]any:
		return inlineObject(components, typed, depth)
	case []any:
		items := make([]any, len(typed))

		for index, item := range typed {
			inlined, err := inlineSchema(components, item, depth+1)
			if err != nil {
				return nil, err
			}

			items[index] = inlined
		}

		return items, nil
	case nil:
		return nil, errors.New("missing schema")
	default:
		return typed, nil
	}
}

// inlineObject inlines one schema object; sibling keywords of a $ref (such as description) are kept.
func inlineObject(components map[string]any, object map[string]any, depth int) (any, error) {
	result := map[string]any{}

	if reference, ok := object[keywordRef].(string); ok {
		name, found := strings.CutPrefix(reference, componentSchemaPrefix)
		if !found {
			return nil, fmt.Errorf("unsupported reference %q", reference)
		}

		component, known := components[name]
		if !known {
			return nil, fmt.Errorf("unknown reference %q", reference)
		}

		resolved, err := inlineSchema(components, component, depth+1)
		if err != nil {
			return nil, err
		}

		resolvedObject, ok := resolved.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("reference %q is not an object schema", reference)
		}

		maps.Copy(result, resolvedObject)
	}

	for key, value := range object {
		if key == keywordRef || dropsOpenAPIKeyword(key) {
			continue
		}

		inlined, err := inlineKeyword(components, key, value, depth)
		if err != nil {
			return nil, err
		}

		result[key] = inlined
	}

	translateNullable(result)
	translateExclusiveBounds(result)

	return result, nil
}

// inlineKeyword inlines nested schemas; keyword values that hold plain data (enum, default,
// required, property names) are copied untouched.
func inlineKeyword(components map[string]any, key string, value any, depth int) (any, error) {
	switch key {
	case keywordProperties, "patternProperties":
		properties, ok := value.(map[string]any)
		if !ok {
			return value, nil
		}

		inlined := make(map[string]any, len(properties))

		for name, property := range properties {
			schema, err := inlineSchema(components, property, depth+1)
			if err != nil {
				return nil, err
			}

			inlined[name] = schema
		}

		return inlined, nil
	case "items", keywordAdditionalProperties, "not", "allOf", "anyOf", "oneOf":
		if flag, isBool := value.(bool); isBool {
			return flag, nil
		}

		return inlineSchema(components, value, depth+1)
	default:
		return value, nil
	}
}

// dropsOpenAPIKeyword reports keywords that have no JSON Schema meaning or carry generator hints.
func dropsOpenAPIKeyword(key string) bool {
	switch key {
	case "example", "discriminator", "xml", "externalDocs":
		return true
	default:
		return strings.HasPrefix(key, "x-")
	}
}

// translateNullable turns OpenAPI 3.0 nullable into a JSON Schema type union.
func translateNullable(object map[string]any) {
	nullable, ok := object["nullable"].(bool)
	delete(object, "nullable")

	if !ok || !nullable {
		return
	}

	if typeName, isText := object["type"].(string); isText {
		object["type"] = []any{typeName, "null"}
	}
}

// translateExclusiveBounds turns OpenAPI 3.0 boolean exclusive bounds into JSON Schema numbers.
func translateExclusiveBounds(object map[string]any) {
	for exclusive, bound := range map[string]string{"exclusiveMinimum": "minimum", "exclusiveMaximum": "maximum"} {
		flag, isBool := object[exclusive].(bool)
		if !isBool {
			continue
		}

		delete(object, exclusive)

		if value, present := object[bound]; flag && present {
			object[exclusive] = value
			delete(object, bound)
		}
	}
}

// Package rest owns the control API boundary and domain-to-DTO adapters.
package rest

import jsoniter "github.com/json-iterator/go"

// JSON is the REST boundary JSON codec. This intentionally uses jsoniter for
// REST JSON paths where the project chooses it over encoding/json.
var JSON = jsoniter.ConfigCompatibleWithStandardLibrary

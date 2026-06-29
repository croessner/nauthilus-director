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

package backend

import "github.com/croessner/nauthilus-director/internal/config"

// PasswordValue resolves the master-user password at the credential sink.
func (c MasterUserConfig) PasswordValue(field string) (string, error) {
	return backendSecretValue(c.Password, c.PasswordFile, field)
}

// PasswordValue resolves the SASL password at the credential sink.
func (c SASLConfig) PasswordValue(field string) (string, error) {
	return backendSecretValue(c.Password, c.PasswordFile, field)
}

// TokenValue resolves the OAuth bearer token at the credential sink.
func (c OAuthBearerConfig) TokenValue(field string) (string, error) {
	return backendSecretValue(c.Token, c.TokenFile, field)
}

// PasswordValue resolves the health-check password at the credential sink.
func (c HealthConfig) PasswordValue(field string) (string, error) {
	return backendSecretValue(c.Password, c.PasswordFile, field)
}

// backendSecretValue reads file-backed backend secrets and preserves inline domain fixtures.
func backendSecretValue(secret config.SecretString, fileBacked bool, field string) (string, error) {
	if fileBacked {
		return config.ReadSecretFile(config.SecretFileOptions{
			Field:    field,
			Path:     secret,
			MaxBytes: config.MaxSecretFileBytes,
		})
	}

	return secret.Value(), nil
}

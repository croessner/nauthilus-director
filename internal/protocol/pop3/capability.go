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

//nolint:wsl_v5 // Capability rendering keeps POP3 wire order compact and visible.
package pop3

import (
	"context"
	"strings"

	"github.com/croessner/nauthilus-director/internal/protocol/certauth"
	"github.com/croessner/nauthilus-director/internal/protocol/saslcred"
	"github.com/croessner/nauthilus-director/internal/protocol/tlscontext"
)

const (
	capabilityPipelining = "PIPELINING"
	capabilityRespCodes  = "RESP-CODES"
	capabilitySASL       = "SASL"
	capabilitySTLS       = "STLS"
	capabilityTop        = "TOP"
	capabilityUIDL       = "UIDL"
	capabilityUser       = "USER"

	authMethodUserPass = "userpass"
)

// handleCapa writes a truthful capability response for the current transport state.
func (s *Session) handleCapa(ctx context.Context, command preauthCommand) error {
	if err := validateNoArguments(command); err != nil {
		s.recordCapability(ctx, pop3ObservationResultRejected, pop3ReasonParser)

		return s.writeERR("Invalid CAPA command")
	}

	if err := s.writeMultilineOK("Capability list follows", s.capabilityLines()); err != nil {
		s.recordCapability(ctx, pop3ObservationResultFailure, pop3ReasonClass(err))

		return err
	}

	s.recordCapability(ctx, pop3ObservationResultOK, pop3ReasonOK)

	return nil
}

// capabilityLines returns the effective authorization-state CAPA set in stable order.
func (s *Session) capabilityLines() []string {
	lines := make([]string, 0, len(s.capabilities)+1)
	seen := make(map[string]struct{}, len(s.capabilities))

	for _, configured := range s.capabilities {
		capability := strings.ToUpper(strings.TrimSpace(configured))
		if capability == "" {
			continue
		}

		if _, exists := seen[capability]; exists {
			continue
		}

		line, ok := s.effectiveCapabilityLine(capability)
		if !ok {
			continue
		}

		seen[capability] = struct{}{}
		lines = append(lines, line)
	}

	return lines
}

// effectiveCapabilityLine returns the current line for one configured capability token.
func (s *Session) effectiveCapabilityLine(capability string) (string, bool) {
	switch capability {
	case capabilitySTLS:
		return capabilitySTLS, s.startTLSAdvertised()
	case capabilityUser:
		return capabilityUser, s.userPassAdvertised()
	case capabilitySASL:
		mechanisms := s.effectiveSASLMechanisms()
		if len(mechanisms) == 0 {
			return "", false
		}

		return capabilitySASL + " " + strings.Join(mechanisms, " "), true
	case capabilityPipelining, capabilityRespCodes, capabilityTop, capabilityUIDL:
		return capability, true
	default:
		return "", false
	}
}

// configuredCapability reports whether listener config permits a capability token.
func (s *Session) configuredCapability(capability string) bool {
	for _, configured := range s.capabilities {
		if strings.EqualFold(strings.TrimSpace(configured), capability) {
			return true
		}
	}

	return false
}

// userPassConfigured reports whether USER/PASS auth is enabled in listener config.
func (s *Session) userPassConfigured() bool {
	for _, mechanism := range s.authMechanisms {
		if strings.EqualFold(strings.TrimSpace(mechanism), authMethodUserPass) {
			return true
		}
	}

	return false
}

// userPassAdvertised reports whether USER/PASS auth can be truthfully used now.
func (s *Session) userPassAdvertised() bool {
	return s.configuredCapability(capabilityUser) && s.userPassConfigured() && s.tlsActive
}

// effectiveSASLMechanisms returns configured SASL mechanisms usable in the current TLS state.
func (s *Session) effectiveSASLMechanisms() []string {
	if !s.tlsActive {
		return nil
	}

	mechanisms := make([]string, 0, len(s.authMechanisms))
	seen := make(map[string]struct{}, len(s.authMechanisms))

	for _, configured := range s.authMechanisms {
		mechanism, err := saslcred.NewMechanism(configured)
		if err != nil {
			continue
		}

		switch mechanism.Normalized() {
		case saslcred.MechanismXOAUTH2, saslcred.MechanismOAuthBearer:
		case saslcred.MechanismExternal:
			if !s.externalAuthAvailable() {
				continue
			}
		default:
			continue
		}

		key := mechanism.Normalized()
		if _, exists := seen[key]; exists {
			continue
		}

		seen[key] = struct{}{}
		mechanisms = append(mechanisms, mechanism.WireName())
	}

	return mechanisms
}

// saslMechanismConfigured reports whether a normalized SASL mechanism is configured.
func (s *Session) saslMechanismConfigured(mechanism string) bool {
	for _, configured := range s.authMechanisms {
		accepted, err := saslcred.NewMechanism(configured)
		if err != nil {
			continue
		}

		if accepted.Normalized() == mechanism {
			return true
		}
	}

	return false
}

// saslMechanismAdvertised reports whether AUTH may use a mechanism now.
func (s *Session) saslMechanismAdvertised(mechanism string) bool {
	for _, advertised := range s.effectiveSASLMechanisms() {
		if strings.EqualFold(advertised, mechanism) {
			return true
		}
	}

	return false
}

// externalAuthAvailable reports whether SASL EXTERNAL can use this connection now.
func (s *Session) externalAuthAvailable() bool {
	state, ok := tlscontext.ConnectionState(s.conn)

	return certauth.Available(s.tlsActive, state, ok)
}

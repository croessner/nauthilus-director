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

package e2e

import (
	"crypto/tls"
	"fmt"
	"testing"

	"github.com/croessner/nauthilus-director/internal/config"
	"github.com/croessner/nauthilus-director/internal/protocol/imap"
)

const (
	e2eBindingAccount         = "native-client@example.test"
	e2eBindingDCRClient       = "dcr-mail-client-4f2a"
	e2eBindingDedicatedClient = "director-imap-introspection"
	e2eBindingDedicatedSecret = "director-imap-introspection-secret-sentinel"
	e2eBindingDCRToken        = "e2e-binding-dcr-token-sentinel"
	e2eBindingNoScopeToken    = "e2e-binding-noscope-token-sentinel"
	e2eBindingWebmailToken    = "e2e-binding-webmail-token-sentinel"
	e2eBindingXOAuth2         = "xoauth2"
	e2eBindingOAuthBearer     = "oauthbearer"
	e2eBindingAuthOAuthBearer = "AUTH=OAUTHBEARER"
	e2eBindingOpenID          = "openid"
	e2eBindingProfile         = "profile"
	e2eBindingAuthXOAuth2     = "AUTH=XOAUTH2"
	e2eBindingIMAP4rev1       = "IMAP4rev1"
	e2eBindingSASLIR          = "SASL-IR"
	e2eBindingSTARTTLS        = "STARTTLS"
)

// dcrStyleToken returns a plain user token issued to a dynamically registered mail client and
// visible only to the listener's dedicated introspection client, as the provider allowlist does.
func dcrStyleToken(scopes []string) fakeSASLBearerToken {
	token := activeFakeSASLBearerToken(e2eBindingAccount, "")
	token.Tenant = ""
	token.Audience = []string{e2eBindingDCRClient}
	token.AuthorizedParty = e2eBindingDCRClient
	token.VisibleTo = e2eBindingDedicatedClient

	if scopes != nil {
		token.Scopes = scopes
	}

	return token
}

// bindingIMAPBearerYAML renders the IMAP listener bearer override for the binding lane.
func bindingIMAPBearerYAML(t *testing.T, tokenBinding string) string {
	t.Helper()

	return fmt.Sprintf(`        bearer:
          token_binding: %s
          introspection_client:
            client_id: %q
            auth_method: client_secret_basic
            client_secret_file: %q
`, tokenBinding, e2eBindingDedicatedClient, writeProcessSecretFile(t, e2eBindingDedicatedSecret))
}

// startBindingIMAPDirector starts one IMAP director whose listener uses the dedicated client.
func startBindingIMAPDirector(t *testing.T, authority *fakeHTTPAuthority, tokenBinding string) (string, *directorProcess) {
	t.Helper()

	redisFixture := startValkeySessionStore(t)
	backendCertPath, _, backendCertificate := writeTestCertificate(t)
	fakeBackend := startFakeIMAPBackend(t, fakeBackendOptions{
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{backendCertificate}, MinVersion: tls.VersionTLS12},
		TLSMode:   imap.TLSModeStartTLS,
	})
	directorAddress := loopbackAddress(t)
	configPath := writeProcessConfig(t, processConfigOptions{
		RedisAddress:    redisFixture.addr,
		AuthorityURL:    authority.URL(),
		AuthorityBearer: processAuthorityBearerForFake(authority),
		DirectorAddress: directorAddress,
		BackendAddress:  fakeBackend.Address(),
		BackendTLS: config.BackendTLSConfig{
			Mode:          sessionProfileBackendTLSMode,
			CAFile:        backendCertPath,
			ServerName:    sessionProfileBackendServerName,
			MinTLSVersion: sessionProfileMinTLSVersion,
		},
		BackendAuth:        masterUserBackendAuthWithBearerReplay([]string{e2eBindingXOAuth2, e2eBindingOAuthBearer}),
		IMAPCapabilities:   []string{e2eBindingIMAP4rev1, e2eBindingSASLIR, e2eBindingSTARTTLS, e2eBindingAuthXOAuth2, e2eBindingAuthOAuthBearer},
		IMAPAuthMechanisms: []string{e2eBindingXOAuth2, e2eBindingOAuthBearer},
		IMAPBearerYAML:     bindingIMAPBearerYAML(t, tokenBinding),
	})
	process := startDirectorProcess(t, e2eServerBinary(t), configPath)
	waitForDirectorGreeting(t, directorAddress, process)

	return directorAddress, process
}

// TestServerBinaryBearerIntrospectionAllowlistBinding proves that a DCR-style token whose audience
// is its own client is accepted only by a listener with the introspection-allowlist binding and a
// dedicated introspection client, that the default binding still refuses it, and that the
// required scope is enforced in both modes.
func TestServerBinaryBearerIntrospectionAllowlistBinding(t *testing.T) {
	webmailToken := activeFakeSASLBearerToken(e2eBindingAccount, "")
	webmailToken.Tenant = ""
	webmailToken.VisibleTo = e2eBindingDedicatedClient

	authority := startMappedFakeOIDCHTTPAuthority(t, bearerAuthorityIdentities(e2eShardTag, e2eBindingAccount), nil, fakeOIDCAuthorityOptions{
		SASLBearerTokens: map[string]fakeSASLBearerToken{
			e2eBindingDCRToken:     dcrStyleToken(nil),
			e2eBindingNoScopeToken: dcrStyleToken([]string{e2eBindingOpenID, e2eBindingProfile}),
			e2eBindingWebmailToken: webmailToken,
		},
		ExtraIntrospectionClients: map[string]string{e2eBindingDedicatedClient: e2eBindingDedicatedSecret},
		SkipBackchannelAuth:       true,
	})

	allowlistAddress, allowlistProcess := startBindingIMAPDirector(t, authority, config.BearerTokenBindingIntrospectionAllowlist)
	imapBearerAuth(t, allowlistAddress, "D001", "XOAUTH2", e2eBindingAccount, e2eBindingDCRToken)
	imapBearerAuth(t, allowlistAddress, "W001", "OAUTHBEARER", e2eBindingAccount, e2eBindingWebmailToken)
	imapBearerAuthFailure(t, allowlistAddress, "S001", "XOAUTH2", e2eBindingAccount, e2eBindingNoScopeToken,
		"S001 NO [AUTHENTICATIONFAILED] Authentication failed\r\n")

	defaultAddress, defaultProcess := startBindingIMAPDirector(t, authority, config.BearerTokenBindingAudienceResource)
	imapBearerAuthFailure(t, defaultAddress, "N001", "XOAUTH2", e2eBindingAccount, e2eBindingDCRToken,
		"N001 NO [AUTHENTICATIONFAILED] Authentication failed\r\n")
	imapBearerAuth(t, defaultAddress, "V001", "XOAUTH2", e2eBindingAccount, e2eBindingWebmailToken)

	for _, process := range []*directorProcess{allowlistProcess, defaultProcess} {
		assertOutputOmits(t, process.output.String(),
			e2eBindingDCRToken, e2eBindingNoScopeToken, e2eBindingWebmailToken, e2eBindingDedicatedSecret)
	}
}

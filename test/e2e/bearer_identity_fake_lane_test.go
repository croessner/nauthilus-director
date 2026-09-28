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
	"bufio"
	"crypto/tls"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus-director/internal/nauthilus"
	"github.com/croessner/nauthilus-director/internal/protocol/imap"
	lmtpbackend "github.com/croessner/nauthilus-director/test/e2e/fakes/lmtp_backend"
	managesievebackend "github.com/croessner/nauthilus-director/test/e2e/fakes/managesieve_backend"
	pop3backend "github.com/croessner/nauthilus-director/test/e2e/fakes/pop3_backend"
)

const (
	e2eBearerRouteIMAPToken     = "e2e-bearer-route-imap-token-sentinel"
	e2eBearerRoutePOP3Token     = "e2e-bearer-route-pop3-token-sentinel"
	e2eBearerRouteSieveToken    = "e2e-bearer-route-sieve-token-sentinel"
	e2eBearerRouteTempfailToken = "e2e-bearer-route-tempfail-token-sentinel"
	e2eBearerRouteCandidates    = 64
)

// bearerRouteAccounts names one hash-routed account per protocol plus the lookup-failure account.
type bearerRouteAccounts struct {
	imap     string
	pop3     string
	sieve    string
	tempfail string
}

// bearerAuthorityIdentities returns no-auth lookup identities that place every account on shard.
func bearerAuthorityIdentities(shard string, accounts ...string) map[string]map[string][]string {
	identities := make(map[string]map[string][]string, len(accounts))
	for _, account := range accounts {
		identities[account] = map[string][]string{
			sessionProfileAttributeAccount: {account},
			e2eAttributeTenant:             {e2eTenant},
			e2eAttributeMailShard:          {shard},
		}
	}

	return identities
}

// expectBearerIdentityLookups verifies each bearer login resolved its token account through the authority.
func expectBearerIdentityLookups(t *testing.T, authority *fakeHTTPAuthority, protocol string, accounts ...string) {
	t.Helper()

	lookups := authority.IdentityLookups()

	for _, account := range accounts {
		found := false

		for _, lookup := range lookups {
			if lookup.Username != account {
				continue
			}

			if lookup.Protocol != protocol || lookup.Method != nauthilus.IdentityLookupMethod {
				t.Fatalf("identity lookup protocol/method = %q/%q, want %s/%s", lookup.Protocol, lookup.Method, protocol, nauthilus.IdentityLookupMethod)
			}

			found = true
		}

		if !found {
			t.Fatalf("authority saw no %s identity lookup for a bearer login", protocol)
		}
	}
}

// bearerTokenWithoutShard returns an active token that names the account but no routing facts.
func bearerTokenWithoutShard(account string) fakeSASLBearerToken {
	token := activeFakeSASLBearerToken(account, "")
	token.Tenant = ""

	return token
}

// bearerRouteLane is the running multiprotocol process with two shards of TLS mailbox backends.
type bearerRouteLane struct {
	authority    *fakeHTTPAuthority
	process      *directorProcess
	ctl          string
	controlURL   string
	imapAddress  string
	pop3sAddress string
	sieveAddress string
	imapA        *fakeIMAPBackend
	imapB        *fakeIMAPBackend
	pop3A        *pop3backend.Server
	pop3B        *pop3backend.Server
	sieveB       *managesievebackend.Server
}

// TestServerBinaryBearerLoginsRouteOnIdentityLookupShard proves IMAP, POP3 and ManageSieve bearer
// logins land on the shard the authority lookup names, even when the hash fallback picks another
// shard, and that a failed lookup tempfails instead of hashing.
func TestServerBinaryBearerLoginsRouteOnIdentityLookupShard(t *testing.T) {
	lane := startBearerRouteLane(t)

	// Identities and tokens are registered once the public route lookup named hash-routed accounts.
	accounts := hashRoutedBearerAccounts(t, lane.ctl, lane.controlURL)
	lane.authority.AddIdentities(bearerAuthorityIdentities(e2eShardTagB, accounts.imap, accounts.pop3, accounts.sieve, accounts.tempfail))
	lane.authority.AddSASLBearerToken(e2eBearerRouteIMAPToken, bearerTokenWithoutShard(accounts.imap))
	lane.authority.AddSASLBearerToken(e2eBearerRoutePOP3Token, bearerTokenWithoutShard(accounts.pop3))
	lane.authority.AddSASLBearerToken(e2eBearerRouteSieveToken, bearerTokenWithoutShard(accounts.sieve))
	lane.authority.AddSASLBearerToken(e2eBearerRouteTempfailToken, bearerTokenWithoutShard(accounts.tempfail))
	lane.authority.FailIdentityLookup(accounts.tempfail)

	exerciseIMAPBearerRoutesOnLookupShard(t, lane.imapAddress, accounts.imap, lane.imapA, lane.imapB)
	exercisePOP3AndSieveBearerRouteOnLookupShard(t, lane, accounts)
	exerciseBearerLookupFailureTempfails(t, lane, accounts.tempfail)

	expectBearerIdentityLookups(t, lane.authority, e2eProtocol, accounts.imap)
	expectBearerIdentityLookups(t, lane.authority, e2ePOP3Protocol, accounts.pop3, accounts.tempfail)
	expectBearerIdentityLookups(t, lane.authority, e2eSieveProtocol, accounts.sieve)

	if lane.authority.PasswordRequestCount() != 0 {
		t.Fatalf("bearer logins used %d password requests, want none", lane.authority.PasswordRequestCount())
	}

	assertOutputOmits(t, lane.process.output.String(),
		e2eBearerRouteIMAPToken, e2eBearerRoutePOP3Token, e2eBearerRouteSieveToken, e2eBearerRouteTempfailToken)
}

// startBearerRouteLane starts the fake authority, TLS mailbox backends on two shards and the director.
func startBearerRouteLane(t *testing.T) *bearerRouteLane {
	t.Helper()

	lane := &bearerRouteLane{
		ctl: buildDirectorctl(t),
		authority: startMappedFakeOIDCHTTPAuthority(t, map[string]map[string][]string{}, nil, fakeOIDCAuthorityOptions{
			SkipBackchannelAuth: true,
		}),
		imapAddress:  loopbackAddress(t),
		pop3sAddress: loopbackAddress(t),
		sieveAddress: loopbackAddress(t),
	}
	redisFixture := startValkeySessionStore(t)

	// Bearer logins replay the token to the mailbox backend, which requires verified backend TLS.
	backendCertPath, _, backendCertificate := writeTestCertificate(t)
	backendTLS := &tls.Config{Certificates: []tls.Certificate{backendCertificate}, MinVersion: tls.VersionTLS12}
	lane.pop3A = pop3backend.Start(t, pop3backend.Options{Messages: pop3SentinelMessages(), TLSConfig: backendTLS, TLSMode: sessionProfileBackendTLSMode})
	lane.pop3B = pop3backend.Start(t, pop3backend.Options{Messages: pop3SentinelMessages(), TLSConfig: backendTLS, TLSMode: sessionProfileBackendTLSMode})
	lane.imapA = startFakeIMAPBackend(t, fakeBackendOptions{TLSConfig: backendTLS, TLSMode: imap.TLSModeStartTLS})
	lane.imapB = startFakeIMAPBackend(t, fakeBackendOptions{TLSConfig: backendTLS, TLSMode: imap.TLSModeStartTLS})
	sieveA := managesievebackend.Start(t, managesievebackend.Options{TLSConfig: backendTLS, TLSMode: sessionProfileBackendTLSMode})
	lane.sieveB = managesievebackend.Start(t, managesievebackend.Options{TLSConfig: backendTLS, TLSMode: sessionProfileBackendTLSMode})
	pop3Address := loopbackAddress(t)
	controlAddress := loopbackAddress(t)
	configPath := writePOP3ProductionProcessConfig(t, pop3ProductionProcessConfigOptions{
		RedisAddress:           redisFixture.addr,
		AuthorityURL:           lane.authority.URL(),
		AuthorityBearer:        processAuthorityBearerForFake(lane.authority),
		POP3Address:            pop3Address,
		POP3SAddress:           lane.pop3sAddress,
		IMAPAddress:            lane.imapAddress,
		LMTPAddress:            loopbackAddress(t),
		SieveAddress:           lane.sieveAddress,
		ControlAddress:         controlAddress,
		POP3Backends:           map[string]string{e2ePOP3BackendAID: lane.pop3A.Address(), e2ePOP3BackendBID: lane.pop3B.Address()},
		IMAPBackends:           map[string]string{e2eBackendAID: lane.imapA.Address(), e2eBackendBID: lane.imapB.Address()},
		LMTPBackends:           map[string]string{e2eLMTPBackendAID: lmtpbackend.Start(t, lmtpbackend.Options{}).Address(), e2eLMTPBackendBID: lmtpbackend.Start(t, lmtpbackend.Options{}).Address()},
		SieveBackends:          map[string]string{e2eSieveBackendAID: sieveA.Address(), e2eSieveBackendBID: lane.sieveB.Address()},
		POP3BackendTLSMode:     sessionProfileBackendTLSMode,
		POP3BackendTLSCAFile:   backendCertPath,
		BearerBackendTLSCAFile: backendCertPath,
		UserHoldMaxWait:        175 * time.Millisecond,
		UserHoldPollInterval:   25 * time.Millisecond,
		IMAPBearer:             true,
		SieveBearer:            true,
	})
	lane.process = startDirectorProcess(t, e2eServerBinary(t), configPath)
	lane.controlURL = "http://" + controlAddress

	waitForPOP3Greeting(t, pop3Address, lane.process)
	waitForTCPListener(t, lane.pop3sAddress, lane.process)
	waitForDirectorGreeting(t, lane.imapAddress, lane.process)
	waitForSieveGreeting(t, lane.sieveAddress, lane.process)
	waitForControlReady(t, lane.controlURL, lane.process)

	return lane
}

// exercisePOP3AndSieveBearerRouteOnLookupShard proves POP3 and ManageSieve bearer sessions reach shard B.
func exercisePOP3AndSieveBearerRouteOnLookupShard(t *testing.T, lane *bearerRouteLane, accounts bearerRouteAccounts) {
	t.Helper()

	pop3Client := dialPOP3TLS(t, lane.pop3sAddress)
	pop3Client.ExpectStatusPrefix("+OK")
	pop3Client.WriteLine(pop3CommandAuth + " XOAUTH2 " + pop3XOAUTH2Payload(accounts.pop3, e2eBearerRoutePOP3Token))
	pop3Client.ExpectStatusPrefix("+OK")
	pop3Client.WriteLine(pop3CommandQuit)
	pop3Client.ExpectStatusPrefix("+OK")
	pop3Client.Close()
	assertPOP3Observation(t, lane.pop3B.ExpectObservation(t), "xoauth2", false)

	sieveClient := dialSieveStartedTLS(t, lane.sieveAddress)
	sieveClient.WriteLine(`AUTHENTICATE "XOAUTH2" "` + sieveXOAUTH2Payload(accounts.sieve, e2eBearerRouteSieveToken) + `"`)
	sieveClient.ExpectStatusPrefix("OK")
	sieveClient.Close()
	assertSieveObservation(t, lane.sieveB.ExpectObservation(t), "xoauth2", false)
}

// exerciseBearerLookupFailureTempfails proves a failed identity lookup tempfails without any backend connection.
func exerciseBearerLookupFailureTempfails(t *testing.T, lane *bearerRouteLane, account string) {
	t.Helper()

	connectionsBefore := lane.pop3A.ConnectionCount() + lane.pop3B.ConnectionCount()
	client := dialPOP3TLS(t, lane.pop3sAddress)
	client.ExpectStatusPrefix("+OK")
	client.WriteLine(pop3CommandAuth + " XOAUTH2 " + pop3XOAUTH2Payload(account, e2eBearerRouteTempfailToken))
	client.ExpectStatusPrefix("-ERR Authentication service temporarily unavailable")
	client.Close()

	if got := lane.pop3A.ConnectionCount() + lane.pop3B.ConnectionCount(); got != connectionsBefore {
		t.Fatalf("POP3 backend connections grew to %d after a failed identity lookup, want %d", got, connectionsBefore)
	}
}

// exerciseIMAPBearerRoutesOnLookupShard proves an IMAP bearer session is proxied to the lookup shard.
func exerciseIMAPBearerRoutesOnLookupShard(t *testing.T, address string, account string, hashBackend *fakeIMAPBackend, lookupBackend *fakeIMAPBackend) {
	t.Helper()

	hashConnections := hashBackend.ConnectionCount()

	client := dialPlain(t, address)
	defer func() { _ = client.Close() }()

	reader := bufio.NewReader(client)
	expectLine(t, reader, "* OK nauthilus-director IMAP session ready\r\n")
	client, reader = upgradeIMAPStartTLS(t, client, reader)
	writeLine(t, client, "R001 AUTHENTICATE XOAUTH2 "+imapXOAUTH2Payload(account, e2eBearerRouteIMAPToken))
	expectLine(t, reader, "R001 OK Authentication completed\r\n")
	expectBackendProxy(t, client, reader, lookupBackend, "R002")

	if hashBackend.ConnectionCount() != hashConnections {
		t.Fatal("IMAP bearer login reached the hash-selected backend")
	}
}

// hashRoutedBearerAccounts asks the public route lookup for accounts whose hash choice is shard A.
func hashRoutedBearerAccounts(t *testing.T, ctl string, controlURL string) bearerRouteAccounts {
	t.Helper()

	var found []string

	for index := range e2eBearerRouteCandidates {
		account := fmt.Sprintf("bearer-route-%d@example.test", index)
		output := runDirectorctl(t, ctl, controlURL,
			"route", "lookup",
			"--protocol", e2ePOP3Protocol,
			"--user", account,
			"--listener", e2ePOP3Listener,
		)

		if strings.Contains(output, "routing_source=hash") && strings.Contains(output, "selected_backend="+e2ePOP3BackendAID) {
			found = append(found, account)
		}

		if len(found) == 4 {
			return bearerRouteAccounts{imap: found[0], pop3: found[1], sieve: found[2], tempfail: found[3]}
		}
	}

	t.Fatal("route lookup found too few accounts whose hash lands on shard A")

	return bearerRouteAccounts{}
}

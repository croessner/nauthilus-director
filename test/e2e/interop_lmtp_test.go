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

//go:build interop

package e2e

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	interopPostfixImage = "chrroessner/postfix:3.11.1"
	interopToolImage    = "debian:trixie-slim"
)

const (
	interopLMTPRecipientA = "interop-ready@example.test"
	interopLMTPRecipientB = "other-b@example.test"
)

// TestDovecotLMTPInterop proves real Postfix-to-Director-to-Dovecot LMTP delivery.
func TestDovecotLMTPInterop(t *testing.T) {
	binary := e2eServerBinary(t)
	dockerCommand := os.Getenv(interopDockerCommandEnv)
	if dockerCommand == "" {
		t.Skipf("%s is required for Postfix LMTP interop", interopDockerCommandEnv)
	}
	imapA := os.Getenv(interopDefaultAAddressEnv)
	imapB := os.Getenv(interopDefaultBAddressEnv)
	lmtpA := os.Getenv(interopDefaultALMTPAddressEnv)
	lmtpB := os.Getenv(interopDefaultBLMTPAddressEnv)
	if imapA == "" || imapB == "" || lmtpA == "" || lmtpB == "" {
		t.Skip("real LMTP interop requires Dovecot IMAP and LMTP backend addresses")
	}

	redisFixture := startValkeySessionStore(t)
	identities := lmtpAuthorityIdentities()
	identities[interopLMTPRecipientA] = lmtpAuthorityIdentity{Account: interopLMTPRecipientA, Tenant: e2eTenant, Shard: e2eShardTag}
	identities[interopLMTPRecipientB] = lmtpAuthorityIdentity{Account: interopLMTPRecipientB, Tenant: e2eTenant, Shard: e2eShardTagB}
	authority := startLMTPAuthority(t, identities)
	tlsBundle := writeLMTPPeerTLSBundle(t)
	lmtpAddress := loopbackAddress(t)
	lmtpsAddress := loopbackAddress(t)
	imapAddress := loopbackAddress(t)
	controlAddress := loopbackAddress(t)
	publishHealthyLMTPBackends(t, redisFixture, []string{e2eLMTPBackendAID, e2eLMTPBackendBID}, "CHUNKING")
	configPath := writeLMTPProcessConfig(t, lmtpProcessConfigOptions{
		RedisAddress:                redisFixture.addr,
		AuthorityURL:                authority.URL(),
		LMTPAddress:                 lmtpAddress,
		LMTPSAddress:                lmtpsAddress,
		IMAPAddress:                 imapAddress,
		ControlAddress:              controlAddress,
		LMTPBackends:                map[string]string{e2eLMTPBackendAID: lmtpA, e2eLMTPBackendBID: lmtpB},
		IMAPBackends:                map[string]string{e2eBackendAID: imapA, e2eBackendBID: imapB},
		TLS:                         tlsBundle,
		DisableLMTPPeerAuth:         true,
		IMAPBackendTLSMode:          "starttls",
		IMAPBackendTLSInsecure:      true,
		IMAPBackendCredentialReplay: true,
		LMTPBackendTLSMode:          "implicit",
		LMTPBackendTLSInsecure:      true,
	})
	process := startDirectorProcess(t, binary, configPath)
	controlURL := "http://" + controlAddress
	waitForLMTPGreeting(t, lmtpAddress, process)
	waitForDirectorGreeting(t, imapAddress, process)
	waitForControlReady(t, controlURL, process)

	proveRealDeliveryHoldPinsIMAP(t, lmtpAddress, imapAddress, controlURL)
	deliveryToken := fmt.Sprintf("real-delivery-%d", time.Now().UnixNano())
	runPostfixSwaksSubmit(t, dockerCommand, lmtpAddress, []string{interopLMTPRecipientA}, deliveryToken)
	assertCurlIMAPSeesDelivery(t, imapA, interopLMTPRecipientA, deliveryToken)
	proveRealDifferentBackendRecipientTempfails(t, lmtpAddress)
	assertLMTPProcessOutputSafe(t, process.output.String())
	if strings.Contains(process.output.String(), interopLMTPRecipientA) || strings.Contains(process.output.String(), interopLMTPRecipientB) {
		t.Fatalf("process output leaked interop recipients: %s", process.output.String())
	}
}

// proveRealDeliveryHoldPinsIMAP verifies real LMTP backend acceptance pins concurrent IMAP placement.
func proveRealDeliveryHoldPinsIMAP(t *testing.T, lmtpAddress string, imapAddress string, controlURL string) {
	t.Helper()

	client := dialLMTP(t, lmtpAddress)
	defer client.Close()
	client.ExpectLine("220 2.0.0 nauthilus-director LMTP ready\r\n")
	client.WriteLine("LHLO interop.example")
	capabilities := client.ReadResponse()
	assertLMTPHasCapability(t, capabilities, "CHUNKING")
	client.WriteLine("MAIL FROM:<sender@example.test>")
	client.ExpectLine("250 2.0.0 Sender accepted\r\n")
	client.WriteLine("RCPT TO:<" + interopLMTPRecipientA + ">")
	client.ExpectLine("250 2.0.0 Recipient accepted\r\n")
	client.WriteLine("RCPT TO:<" + interopLMTPRecipientA + ">")
	client.ExpectLine("250 2.0.0 Recipient accepted\r\n")

	imapClient, imapReader := loginIMAP(t, imapAddress, interopLMTPRecipientA)
	defer func() { _ = imapClient.Close() }()
	writeLine(t, imapClient, "A002 NOOP")
	response := readLine(t, imapReader)
	if !strings.HasPrefix(response, "A002 OK") {
		t.Fatalf("Dovecot NOOP response = %q, want OK", response)
	}
	ctl := buildDirectorctl(t)
	sessions := waitForDirectorctlSessions(t, ctl, controlURL, 1)
	filtered := sessionsForUser(sessions, interopLMTPRecipientA)
	if len(filtered) != 1 || filtered[0].Backend != e2eBackendAID {
		t.Fatalf("IMAP session = %#v, want same shard backend %s", filtered, e2eBackendAID)
	}

	client.WriteLine("DATA")
	client.ExpectLine("354 2.0.0 End data with <CR><LF>.<CR><LF>\r\n")
	client.WriteRaw("Subject: hold proof\r\n\r\nreal backend body\r\n.\r\n")
	client.ExpectLine("250 2.0.0 Message accepted\r\n")
	client.ExpectLine("250 2.0.0 Message accepted\r\n")
}

// proveRealDifferentBackendRecipientTempfails verifies mixed-shard recipients fail before DATA.
func proveRealDifferentBackendRecipientTempfails(t *testing.T, lmtpAddress string) {
	t.Helper()

	client := dialLMTP(t, lmtpAddress)
	defer client.Close()
	client.ExpectLine("220 2.0.0 nauthilus-director LMTP ready\r\n")
	client.WriteLine("LHLO interop-different.example")
	client.ReadResponse()
	client.WriteLine("MAIL FROM:<sender@example.test>")
	client.ExpectLine("250 2.0.0 Sender accepted\r\n")
	client.WriteLine("RCPT TO:<" + interopLMTPRecipientA + ">")
	client.ExpectLine("250 2.0.0 Recipient accepted\r\n")
	client.WriteLine("RCPT TO:<" + interopLMTPRecipientB + ">")
	client.ExpectLine("451 4.3.2 Recipient must be retried separately\r\n")
	client.WriteLine("RSET")
	client.ExpectLine("250 2.0.0 Transaction reset\r\n")
}

// runPostfixSwaksSubmit injects one SMTP message into real Postfix with swaks.
func runPostfixSwaksSubmit(t *testing.T, dockerCommand string, directorAddress string, recipients []string, deliveryToken string) {
	t.Helper()

	containerID, smtpAddress := startPostfixSMTPRelay(t, dockerCommand, directorAddress)
	_, port, err := net.SplitHostPort(smtpAddress)
	if err != nil {
		t.Fatalf("parse mapped Postfix SMTP address %q: %v", smtpAddress, err)
	}

	args := []string{
		"--server", "host.docker.internal",
		"--port", port,
		"--protocol", "SMTP",
		"--from", "sender@example.test",
		"--timeout", "10",
		"--h-Subject", "Director LMTP interop " + deliveryToken,
		"--body", "Postfix to Director to Dovecot " + deliveryToken,
		"--suppress-data",
		"--hide-all",
		"--silent", "3",
	}
	for _, recipient := range recipients {
		args = append(args, "--to", recipient)
	}
	output, err := runContainerTool(t, dockerCommand, "swaks", args...)
	if err != nil {
		t.Fatalf("swaks Postfix submission failed: %v\n%s", err, redactInteropOutput(string(output), deliveryToken))
	}
	waitForPostfixQueueEmpty(t, dockerCommand, containerID, deliveryToken)
}

// startPostfixSMTPRelay starts real Postfix as an SMTP peer relaying to Director LMTP.
func startPostfixSMTPRelay(t *testing.T, dockerCommand string, directorAddress string) (string, string) {
	t.Helper()

	_, port, err := net.SplitHostPort(directorAddress)
	if err != nil {
		t.Fatalf("parse director LMTP address %q: %v", directorAddress, err)
	}
	if _, err := strconv.Atoi(port); err != nil {
		t.Fatalf("parse director LMTP port %q: %v", port, err)
	}

	script := fmt.Sprintf(`
set -eu
postconf -e 'maillog_file = /dev/stdout'
postconf -e 'inet_protocols = ipv4'
postconf -e 'myhostname = postfix-lmtp-e2e.local'
postconf -e 'inet_interfaces = all'
postconf -e 'mydestination ='
postconf -e 'mynetworks = 0.0.0.0/0'
postconf -e 'smtpd_recipient_restrictions = permit_mynetworks,reject_unauth_destination'
postconf -e 'local_transport = error:local delivery disabled'
postconf -e 'default_transport = lmtp:inet:host.docker.internal:%s'
postconf -e 'lmtp_tls_security_level = none'
postfix start
trap 'postfix stop >/dev/null 2>&1 || true' EXIT
while :; do
	sleep 3600
done
`, port)

	cmd := exec.Command(
		dockerCommand,
		"run",
		"--detach",
		"--pull=missing",
		"--publish", "127.0.0.1::25",
		"--add-host", "host.docker.internal:host-gateway",
		"--entrypoint", "sh",
		interopPostfixImage,
		"-c",
		script,
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("start Postfix SMTP relay failed: %v\n%s", err, redactInteropOutput(string(output), ""))
	}
	containerID := strings.TrimSpace(string(output))
	t.Cleanup(func() {
		_ = exec.Command(dockerCommand, "rm", "-f", containerID).Run()
	})

	smtpAddress := waitForDockerMappedPort(t, dockerCommand, containerID, "25/tcp")
	waitForSMTPGreeting(t, smtpAddress)

	return containerID, smtpAddress
}

// waitForDockerMappedPort waits until Docker reports a published container port.
func waitForDockerMappedPort(t *testing.T, dockerCommand string, containerID string, containerPort string) string {
	t.Helper()

	var lastOutput string
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		output, err := exec.Command(dockerCommand, "port", containerID, containerPort).CombinedOutput()
		lastOutput = strings.TrimSpace(string(output))
		if err == nil && lastOutput != "" {
			return strings.Split(lastOutput, "\n")[0]
		}

		time.Sleep(100 * time.Millisecond)
	}

	t.Fatalf("Docker did not publish %s for Postfix container %s: %s", containerPort, containerID, lastOutput)
	return ""
}

// waitForSMTPGreeting waits until the Postfix container accepts public SMTP.
func waitForSMTPGreeting(t *testing.T, smtpAddress string) {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", smtpAddress, 200*time.Millisecond)
		if err == nil {
			_ = conn.SetDeadline(time.Now().Add(time.Second))
			line, readErr := bufio.NewReader(conn).ReadString('\n')
			_ = conn.Close()
			if readErr == nil && strings.HasPrefix(line, "220 ") {
				return
			}
		}

		time.Sleep(100 * time.Millisecond)
	}

	t.Fatalf("Postfix SMTP relay did not become ready at %s", smtpAddress)
}

// waitForPostfixQueueEmpty waits until Postfix has handed the message to LMTP.
func waitForPostfixQueueEmpty(t *testing.T, dockerCommand string, containerID string, deliveryToken string) {
	t.Helper()

	var lastOutput string
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		_, _ = exec.Command(dockerCommand, "exec", containerID, "postqueue", "-f").CombinedOutput()
		output, err := exec.Command(dockerCommand, "exec", containerID, "mailq").CombinedOutput()
		lastOutput = string(output)
		if err == nil && strings.Contains(lastOutput, "Mail queue is empty") {
			return
		}

		time.Sleep(250 * time.Millisecond)
	}

	t.Fatalf("Postfix queue did not drain after swaks submission:\n%s", redactInteropOutput(lastOutput, deliveryToken))
}

// assertCurlIMAPSeesDelivery searches the real Dovecot backend for the delivered message.
func assertCurlIMAPSeesDelivery(t *testing.T, imapAddress string, account string, deliveryToken string) {
	t.Helper()

	url := imapToolURL(imapAddress, "INBOX")
	request := fmt.Sprintf("SEARCH TEXT %q", deliveryToken)
	var lastOutput string
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		output, runErr := runContainerTool(
			t,
			dockerCommandFromEnv(t),
			"curl",
			"--silent",
			"--show-error",
			"--fail",
			"--ssl-reqd",
			"--insecure",
			"--user", account+":"+e2ePassword,
			"--url", url,
			"--request", request,
		)
		lastOutput = string(output)
		if runErr == nil && imapSearchHasHit(lastOutput) {
			return
		}

		time.Sleep(250 * time.Millisecond)
	}

	t.Fatalf("curl IMAP search did not find delivered Postfix message:\n%s", redactInteropOutput(lastOutput, deliveryToken))
}

// dockerCommandFromEnv returns the Docker command configured for interop tests.
func dockerCommandFromEnv(t *testing.T) string {
	t.Helper()

	dockerCommand := os.Getenv(interopDockerCommandEnv)
	if dockerCommand == "" {
		t.Fatalf("%s is required for containerized interop tools", interopDockerCommandEnv)
	}

	return dockerCommand
}

// runContainerTool installs and runs a mail-test tool inside a short-lived tool container.
func runContainerTool(t *testing.T, dockerCommand string, tool string, args ...string) ([]byte, error) {
	t.Helper()

	command := []string{
		"run",
		"--rm",
		"--pull=missing",
		"--add-host", "host.docker.internal:host-gateway",
		"--entrypoint", "sh",
		interopToolImage,
		"-ec",
		"export DEBIAN_FRONTEND=noninteractive; apt-get update >/dev/null && apt-get install -y --no-install-recommends ca-certificates curl swaks >/dev/null && exec \"$@\"",
		tool,
		tool,
	}
	command = append(command, args...)

	return exec.Command(dockerCommand, command...).CombinedOutput()
}

// imapToolURL returns a curl IMAP URL reachable from the tool container.
func imapToolURL(address string, mailbox string) string {
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		return "imap://" + address + "/" + mailbox
	}

	return fmt.Sprintf("imap://host.docker.internal:%s/%s", port, mailbox)
}

// imapSearchHasHit reports whether a curl IMAP SEARCH response includes a result id.
func imapSearchHasHit(output string) bool {
	for _, field := range strings.Fields(output) {
		if _, err := strconv.Atoi(field); err == nil {
			return true
		}
	}

	return false
}

// redactInteropOutput removes known sensitive or high-cardinality interop values.
func redactInteropOutput(output string, deliveryToken string) string {
	replacer := strings.NewReplacer(
		e2ePassword, "<redacted-password>",
		e2eLMTPMessageSecret, "<redacted-message-secret>",
		interopLMTPRecipientA, "<redacted-recipient>",
		interopLMTPRecipientB, "<redacted-recipient>",
	)
	redacted := replacer.Replace(output)
	if deliveryToken != "" {
		redacted = strings.ReplaceAll(redacted, deliveryToken, "<redacted-delivery-token>")
	}

	return redacted
}

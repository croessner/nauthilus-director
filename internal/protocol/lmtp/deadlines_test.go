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

package lmtp

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

const (
	testDeadlinePreauth  = 200 * time.Millisecond
	testDeadlineResponse = 5 * time.Second
)

// TestSlowDATAAndEndOfDataOutlastPreauthTimeout reproduces sessions that were cut after the preauth timeout.
func TestSlowDATAAndEndOfDataOutlastPreauthTimeout(t *testing.T) {
	sink := &slowFinishMessageSink{delay: 2 * testDeadlinePreauth}
	config := testDeadlineSessionConfig(time.Second, 5*time.Second)
	config.MessageSink = sink

	harness := startDeadlineHarness(t, config)
	placeDeadlineRecipient(t, harness)
	harness.write(t, "DATA\r\n")
	harness.expectLine(t, "354 2.0.0 End data with <CR><LF>.<CR><LF>\r\n")

	for _, line := range []string{"line-one\r\n", "line-two\r\n", "line-three\r\n"} {
		time.Sleep(testDeadlinePreauth / 2)
		harness.write(t, line)
	}

	harness.write(t, ".\r\n")
	harness.expectLine(t, "250 2.0.0 Message accepted\r\n")
	harness.write(t, "QUIT\r\n")
	harness.expectLine(t, "221 2.0.0 Bye\r\n")
	harness.expectDone(t)

	if sink.finishes() != 1 {
		t.Fatalf("finish count = %d, want 1", sink.finishes())
	}
}

// TestBackendEndOfDataOutlastsPreauthAndIdleTimeouts keeps slow backend final replies within the data phase.
func TestBackendEndOfDataOutlastsPreauthAndIdleTimeouts(t *testing.T) {
	const finalDelay = 3 * testDeadlinePreauth

	for _, tc := range []struct {
		name   string
		script func(*testing.T, net.Conn)
	}{
		{
			name: "data",
			script: func(t *testing.T, conn net.Conn) {
				reader := greetTransactionBackend(t, conn)
				expectBackendEnvelope(t, conn, reader)
				expectLMTPBackendLine(t, reader, "DATA")
				writeLMTPBackendLine(t, conn, "354 2.0.0 send data")
				expectLMTPBackendLine(t, reader, "line-one")
				expectLMTPBackendLine(t, reader, ".")
				time.Sleep(finalDelay)
				writeLMTPBackendLine(t, conn, "250 2.0.0 delivered")
			},
		},
		{
			name: "bdat",
			script: func(t *testing.T, conn net.Conn) {
				reader := greetChunkingTransactionBackend(t, conn)
				expectBackendEnvelope(t, conn, reader)
				expectLMTPBackendLine(t, reader, "BDAT 10 LAST")
				expectLMTPBackendBytes(t, reader, "line-one\r\n")
				time.Sleep(finalDelay)
				writeLMTPBackendLine(t, conn, "250 2.0.0 delivered")
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dialer := scriptedLMTPBackendDialer(t, tc.script)
			config := deadlineBackendSessionConfig(dialer, 2*testDeadlinePreauth, 5*time.Second)

			harness := startDeadlineHarness(t, config)
			placeDeadlineRecipient(t, harness)
			harness.write(t, "DATA\r\n")
			harness.expectLine(t, "354 2.0.0 End data with <CR><LF>.<CR><LF>\r\n")
			harness.write(t, "line-one\r\n.\r\n")
			harness.expectLine(t, "250 2.0.0 Message accepted\r\n")
			dialer.Wait(t)
		})
	}
}

// TestStalledPeerAfterPlacementIsCutByIdleTimeout keeps idle cuts once preauth no longer applies.
func TestStalledPeerAfterPlacementIsCutByIdleTimeout(t *testing.T) {
	const idle = 2 * testDeadlinePreauth

	sink := &slowFinishMessageSink{}
	config := testDeadlineSessionConfig(idle, 5*time.Second)
	config.MessageSink = sink

	harness := startDeadlineHarness(t, config)
	placeDeadlineRecipient(t, harness)
	time.Sleep(testDeadlinePreauth + testDeadlinePreauth/2)
	harness.write(t, "DATA\r\n")
	harness.expectLine(t, "354 2.0.0 End data with <CR><LF>.<CR><LF>\r\n")
	harness.write(t, "line-one\r\n")

	stalled := time.Now()

	harness.expectTimeoutDone(t, 10*idle)

	if elapsed := time.Since(stalled); elapsed < idle/2 {
		t.Fatalf("stalled body cut after %s, want about the idle timeout %s", elapsed, idle)
	}

	if sink.aborts() != 1 {
		t.Fatalf("abort count = %d, want 1", sink.aborts())
	}
}

// TestStalledPeerBetweenCommandsAfterPlacementIsCutByIdleTimeout bounds silent placed sessions.
func TestStalledPeerBetweenCommandsAfterPlacementIsCutByIdleTimeout(t *testing.T) {
	const idle = 2 * testDeadlinePreauth

	config := testDeadlineSessionConfig(idle, 5*time.Second)
	config.MessageSink = &slowFinishMessageSink{}

	harness := startDeadlineHarness(t, config)
	placeDeadlineRecipient(t, harness)
	harness.expectTimeoutDone(t, 10*idle)
}

// TestTricklingDATAPeerIsCutByDataTimeout bounds a peer that keeps making slow progress.
func TestTricklingDATAPeerIsCutByDataTimeout(t *testing.T) {
	const dataTimeout = 4 * testDeadlinePreauth

	sink := &slowFinishMessageSink{}
	config := testDeadlineSessionConfig(2*testDeadlinePreauth, dataTimeout)
	config.MessageSink = sink

	harness := startDeadlineHarness(t, config)
	placeDeadlineRecipient(t, harness)
	harness.write(t, "DATA\r\n")
	harness.expectLine(t, "354 2.0.0 End data with <CR><LF>.<CR><LF>\r\n")

	started := time.Now()
	stop := make(chan struct{})
	trickled := make(chan struct{})

	go func() {
		defer close(trickled)

		for {
			select {
			case <-stop:
				return
			case <-time.After(testDeadlinePreauth / 4):
			}

			if _, err := harness.client.Write([]byte("trickle\r\n")); err != nil {
				return
			}
		}
	}()

	harness.expectTimeoutDone(t, 10*dataTimeout)
	close(stop)
	<-trickled

	if elapsed := time.Since(started); elapsed < dataTimeout*3/4 {
		t.Fatalf("trickling DATA cut after %s, want about the data timeout %s", elapsed, dataTimeout)
	}
}

// TestPreauthTimeoutStillBoundsUnplacedSession keeps the absolute bound before any recipient is accepted.
func TestPreauthTimeoutStillBoundsUnplacedSession(t *testing.T) {
	config := testDeadlineSessionConfig(5*time.Second, 5*time.Second)
	config.MessageSink = &slowFinishMessageSink{}

	harness := startDeadlineHarness(t, config)
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.drainLHLO(t)

	stop := make(chan struct{})
	pinged := make(chan struct{})

	go func() {
		defer close(pinged)

		reader := harness.reader

		for {
			select {
			case <-stop:
				return
			case <-time.After(testDeadlinePreauth / 4):
			}

			if _, err := harness.client.Write([]byte("NOOP\r\n")); err != nil {
				return
			}

			if _, err := reader.ReadString('\n'); err != nil {
				return
			}
		}
	}()

	harness.expectTimeoutDone(t, 10*testDeadlinePreauth)
	close(stop)

	_ = harness.client.Close()

	<-pinged
}

// TestStalledBackendEndOfDataTempfailsAtDataTimeout keeps a silent backend from holding the session forever.
func TestStalledBackendEndOfDataTempfailsAtDataTimeout(t *testing.T) {
	const dataTimeout = 4 * testDeadlinePreauth

	dialer := scriptedLMTPBackendDialer(t, func(t *testing.T, conn net.Conn) {
		reader := greetTransactionBackend(t, conn)
		expectBackendEnvelope(t, conn, reader)
		expectLMTPBackendLine(t, reader, "DATA")
		writeLMTPBackendLine(t, conn, "354 2.0.0 send data")
		expectLMTPBackendLine(t, reader, "line-one")
		expectLMTPBackendLine(t, reader, ".")
		_, _ = io.Copy(io.Discard, reader)
	})
	config := deadlineBackendSessionConfig(dialer, 2*testDeadlinePreauth, dataTimeout)

	harness := startDeadlineHarness(t, config)
	placeDeadlineRecipient(t, harness)
	harness.write(t, "DATA\r\n")
	harness.expectLine(t, "354 2.0.0 End data with <CR><LF>.<CR><LF>\r\n")

	started := time.Now()

	harness.write(t, "line-one\r\n.\r\n")
	harness.expectLine(t, testTemporaryDelivery)

	if elapsed := time.Since(started); elapsed < dataTimeout*3/4 {
		t.Fatalf("stalled backend tempfailed after %s, want about the data timeout %s", elapsed, dataTimeout)
	}

	dialer.Wait(t)
}

// testDeadlineSessionConfig returns a frontend-only session with short phase timeouts.
func testDeadlineSessionConfig(idle time.Duration, data time.Duration) SessionConfig {
	config := testSessionConfig()
	config.TLSMode = TLSModeImplicit
	config.Capabilities = []string{capabilitySMTPUTF8}
	config.PreauthTimeout = testDeadlinePreauth
	config.CommandIdleTimeout = idle
	config.DataTimeout = data

	return config
}

// deadlineBackendSessionConfig returns a backend-forwarding session with short phase timeouts.
func deadlineBackendSessionConfig(dialer BackendDialer, idle time.Duration, data time.Duration) SessionConfig {
	identity := identityLookuperForRecipients(map[string]string{testRecipientSingle: testPlacementShardA})
	config := backendForwardingSessionConfig(identity, &recordingRoutingResolver{}, &recordingDeliveryStore{}, &recordingBackendSelector{}, dialer)
	config.PreauthTimeout = testDeadlinePreauth
	config.CommandIdleTimeout = idle
	config.DataTimeout = data

	return config
}

// startDeadlineHarness starts a session whose client I/O cannot hang the test.
func startDeadlineHarness(t *testing.T, config SessionConfig) *lmtpHarness {
	t.Helper()

	harness := startLMTPHarness(t, config)
	if err := harness.client.SetDeadline(time.Now().Add(testDeadlineResponse)); err != nil {
		t.Fatalf("set client deadline: %v", err)
	}

	return harness
}

// placeDeadlineRecipient runs greeting, LHLO, MAIL and one accepted RCPT.
func placeDeadlineRecipient(t *testing.T, harness *lmtpHarness) {
	t.Helper()

	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.drainLHLO(t)
	harness.write(t, "MAIL FROM:<sender@example.test>\r\n")
	harness.expectLine(t, "250 2.0.0 Sender accepted\r\n")
	harness.write(t, "RCPT TO:<"+testRecipientSingle+">\r\n")
	harness.expectLine(t, "250 2.0.0 Recipient accepted\r\n")
}

// expectBackendEnvelope accepts the forwarded MAIL and RCPT commands for one recipient.
func expectBackendEnvelope(t *testing.T, conn net.Conn, reader *bufio.Reader) {
	t.Helper()

	expectLMTPBackendLine(t, reader, "MAIL FROM:<sender@example.test>")
	writeLMTPBackendLine(t, conn, "250 2.1.0 sender ok")
	expectLMTPBackendLine(t, reader, "RCPT TO:<"+testRecipientSingle+">")
	writeLMTPBackendLine(t, conn, "250 2.1.5 recipient ok")
}

// expectTimeoutDone waits for the session to end with a network timeout.
func (h *lmtpHarness) expectTimeoutDone(t *testing.T, within time.Duration) {
	t.Helper()

	select {
	case err := <-h.done:
		h.done = nil

		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			t.Fatalf("session error = %v, want network timeout", err)
		}
	case <-time.After(within):
		t.Fatalf("session was not cut within %s", within)
	}
}

type slowFinishMessageSink struct {
	recordingMessageSink

	delay time.Duration
}

// OpenMessage returns the sink itself so Finish can model slow end-of-data handling.
func (s *slowFinishMessageSink) OpenMessage(ctx context.Context, snapshot TransactionSnapshot) (MessageBody, error) {
	if _, err := s.recordingMessageSink.OpenMessage(ctx, snapshot); err != nil {
		return nil, err
	}

	return s, nil
}

// Finish waits before completing to model slow backend end-of-data processing.
func (s *slowFinishMessageSink) Finish(ctx context.Context) (MessageResult, error) {
	time.Sleep(s.delay)

	return s.recordingMessageSink.Finish(ctx)
}

// finishes returns the number of completed messages.
func (s *slowFinishMessageSink) finishes() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.finish
}

// aborts returns the number of aborted messages.
func (s *slowFinishMessageSink) aborts() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.abort
}

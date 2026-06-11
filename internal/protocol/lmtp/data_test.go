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
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

const (
	testAbortReasonDataStream = "data_stream"
	testDATALineDot           = ".\r\n"
	testDATALineHello         = "hello\r\n"
)

type recordedBDATPayload struct {
	payload        []byte
	last           bool
	recipientCount int
}

type recordingBDATPayloadSender struct {
	chunks          []recordedBDATPayload
	nonFinalResults []MessageResult
	finalResult     MessageResult
	errAt           int
	err             error
	nonFinalCalls   int
	closeReasons    []string
}

// TestBackendBDATBodyUnstuffsAndPreservesDATAExamples verifies DATA decoding examples.
func TestBackendBDATBodyUnstuffsAndPreservesDATAExamples(t *testing.T) {
	tests := []struct {
		name string
		line string
		want string
	}{
		{
			name: "plain line",
			line: testDATALineHello,
			want: testDATALineHello,
		},
		{
			name: "dot stuffed text",
			line: "..hello\r\n",
			want: "." + testDATALineHello,
		},
		{
			name: "dot stuffed dot content",
			line: "..\r\n",
			want: testDATALineDot,
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			sender := newRecordingBDATPayloadSender()
			body := newBackendBDATBody(sender, 1, 32)

			written, err := body.WriteDATALine([]byte(testCase.line))
			if err != nil {
				t.Fatalf("WriteDATALine returned error: %v", err)
			}

			if written != len(testCase.line) {
				t.Fatalf("WriteDATALine wrote %d bytes, want %d", written, len(testCase.line))
			}

			result, err := body.Finish(context.Background())
			if err != nil {
				t.Fatalf("Finish returned error: %v", err)
			}

			if !reflect.DeepEqual(result, sender.finalResult) {
				t.Fatalf("Finish result = %#v, want %#v", result, sender.finalResult)
			}

			assertBDATPayloads(t, sender.chunks, []recordedBDATPayload{
				{payload: []byte(testCase.want), last: true, recipientCount: 1},
			})
		})
	}
}

// TestBackendBDATBodyStreamDATAOmitsTerminator proves streamDATA keeps the terminator out.
func TestBackendBDATBodyStreamDATAOmitsTerminator(t *testing.T) {
	sender := newRecordingBDATPayloadSender()
	body := newBackendBDATBody(sender, 1, 32)
	session := &Session{
		reader:       bufio.NewReader(strings.NewReader("body\r\n.\r\n")),
		maxLineBytes: 64,
	}

	writeFailed, err := session.streamDATA(context.Background(), body)
	if err != nil {
		t.Fatalf("streamDATA returned error: %v", err)
	}

	if writeFailed {
		t.Fatal("streamDATA reported a write failure")
	}

	if _, err := body.Finish(context.Background()); err != nil {
		t.Fatalf("Finish returned error: %v", err)
	}

	assertBDATPayloads(t, sender.chunks, []recordedBDATPayload{
		{payload: []byte("body\r\n"), last: true, recipientCount: 1},
	})
}

// TestMessageSizeCounterCountsDecodedDATABytes verifies DATA accounting follows transfer decoding.
func TestMessageSizeCounterCountsDecodedDATABytes(t *testing.T) {
	counter := newMessageSizeCounter(10)

	if err := counter.CountDATA([]byte("hello\r\n")); err != nil {
		t.Fatalf("CountDATA plain line returned error: %v", err)
	}

	if err := counter.CountDATA([]byte("..\r\n")); err != nil {
		t.Fatalf("CountDATA dot-stuffed line returned error: %v", err)
	}

	if err := counter.CountDATA([]byte("x\r\n")); !errors.Is(err, errMessageSizeExceeded) {
		t.Fatalf("CountDATA overflow error = %v, want size exceeded", err)
	}
}

// TestMessageSizeCounterCountsBDATAnnouncedSizes verifies BDAT accounting uses chunk sizes.
func TestMessageSizeCounterCountsBDATAnnouncedSizes(t *testing.T) {
	counter := newMessageSizeCounter(5)

	if err := counter.CountBDAT(2); err != nil {
		t.Fatalf("CountBDAT first chunk returned error: %v", err)
	}

	if err := counter.CountBDAT(3); err != nil {
		t.Fatalf("CountBDAT exact maximum returned error: %v", err)
	}

	if err := counter.CountBDAT(1); !errors.Is(err, errMessageSizeExceeded) {
		t.Fatalf("CountBDAT overflow error = %v, want size exceeded", err)
	}
}

// TestBackendBDATBodyFinishEmptySendsFinalEmptyPayload verifies BDAT 0 LAST behavior.
func TestBackendBDATBodyFinishEmptySendsFinalEmptyPayload(t *testing.T) {
	sender := newRecordingBDATPayloadSender()
	body := newBackendBDATBody(sender, 1, 32)

	if _, err := body.Finish(context.Background()); err != nil {
		t.Fatalf("Finish returned error: %v", err)
	}

	assertBDATPayloads(t, sender.chunks, []recordedBDATPayload{
		{payload: []byte{}, last: true, recipientCount: 1},
	})
}

// TestBackendBDATBodyFinishAfterExactChunkSendsFinalEmptyPayload verifies trailing empty LAST.
func TestBackendBDATBodyFinishAfterExactChunkSendsFinalEmptyPayload(t *testing.T) {
	sender := newRecordingBDATPayloadSender()
	body := newBackendBDATBody(sender, 1, 4)

	if _, err := body.WriteDATALine([]byte("ab\r\n")); err != nil {
		t.Fatalf("WriteDATALine returned error: %v", err)
	}

	if _, err := body.Finish(context.Background()); err != nil {
		t.Fatalf("Finish returned error: %v", err)
	}

	assertBDATPayloads(t, sender.chunks, []recordedBDATPayload{
		{payload: []byte("ab\r\n"), recipientCount: 1},
		{payload: []byte{}, last: true, recipientCount: 1},
	})
}

// TestBackendBDATBodyFlushesBoundedChunks verifies deterministic non-final flushing.
func TestBackendBDATBodyFlushesBoundedChunks(t *testing.T) {
	sender := newRecordingBDATPayloadSender()
	body := newBackendBDATBody(sender, 3, 4)

	if _, err := body.WriteDATALine([]byte("abcdefghi\r\n")); err != nil {
		t.Fatalf("WriteDATALine returned error: %v", err)
	}

	if _, err := body.Finish(context.Background()); err != nil {
		t.Fatalf("Finish returned error: %v", err)
	}

	assertBDATPayloads(t, sender.chunks, []recordedBDATPayload{
		{payload: []byte("abcd"), recipientCount: 3},
		{payload: []byte("efgh"), recipientCount: 3},
		{payload: []byte("i\r\n"), last: true, recipientCount: 3},
	})
}

// TestBackendBDATBodyNonFinalFailureStopsWriter verifies rejected and failed chunks stop writes.
func TestBackendBDATBodyNonFinalFailureStopsWriter(t *testing.T) {
	errPayloadWrite := errors.New("test backend bdat payload write failure")
	tests := []struct {
		name    string
		sender  *recordingBDATPayloadSender
		wantErr error
	}{
		{
			name: "payload write failure",
			sender: &recordingBDATPayloadSender{
				finalResult: defaultBDATFinalResult(),
				err:         errPayloadWrite,
			},
			wantErr: errPayloadWrite,
		},
		{
			name: "chunk rejection",
			sender: &recordingBDATPayloadSender{
				finalResult: defaultBDATFinalResult(),
				nonFinalResults: []MessageResult{
					{Statuses: []DeliveryStatus{{Status: responseStatusTemporary, Enhanced: enhancedTemporary, Text: backendDeliveryTemporaryText}}},
				},
			},
			wantErr: errBackendBDATChunkRejected,
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			body := newBackendBDATBody(testCase.sender, 1, 4)

			if _, err := body.WriteDATALine([]byte("abcdef\r\n")); !errors.Is(err, testCase.wantErr) {
				t.Fatalf("WriteDATALine error = %v, want %v", err, testCase.wantErr)
			}

			if _, err := body.WriteDATALine([]byte("next\r\n")); !errors.Is(err, testCase.wantErr) {
				t.Fatalf("second WriteDATALine error = %v, want %v", err, testCase.wantErr)
			}

			if _, err := body.Finish(context.Background()); !errors.Is(err, testCase.wantErr) {
				t.Fatalf("Finish error = %v, want %v", err, testCase.wantErr)
			}

			if got := len(testCase.sender.chunks); got != 1 {
				t.Fatalf("backend BDAT payload chunks = %d, want 1", got)
			}
		})
	}
}

// TestBackendBDATBodyFinishReturnsFinalSenderResult verifies final statuses are passed through.
func TestBackendBDATBodyFinishReturnsFinalSenderResult(t *testing.T) {
	finalResult := MessageResult{
		Statuses: []DeliveryStatus{
			{Status: responseStatusTemporary, Enhanced: enhancedTemporary, Text: backendDeliveryTemporaryText},
		},
	}
	sender := &recordingBDATPayloadSender{finalResult: finalResult}
	body := newBackendBDATBody(sender, 1, 32)

	if _, err := body.WriteDATALine([]byte("body\r\n")); err != nil {
		t.Fatalf("WriteDATALine returned error: %v", err)
	}

	result, err := body.Finish(context.Background())
	if err != nil {
		t.Fatalf("Finish returned error: %v", err)
	}

	if !reflect.DeepEqual(result, finalResult) {
		t.Fatalf("Finish result = %#v, want %#v", result, finalResult)
	}

	assertBDATPayloads(t, sender.chunks, []recordedBDATPayload{
		{payload: []byte("body\r\n"), last: true, recipientCount: 1},
	})
}

// TestBackendBDATBodyAbortClosesSender verifies partial DATA-to-BDAT cleanup.
func TestBackendBDATBodyAbortClosesSender(t *testing.T) {
	sender := newRecordingBDATPayloadSender()
	body := newBackendBDATBody(sender, 1, 32)

	if _, err := body.WriteDATALine([]byte("body\r\n")); err != nil {
		t.Fatalf("WriteDATALine returned error: %v", err)
	}

	if err := body.Abort(context.Background(), testAbortReasonDataStream); err != nil {
		t.Fatalf("Abort returned error: %v", err)
	}

	if _, err := body.WriteDATALine([]byte("after\r\n")); !errors.Is(err, errBackendBDATBodyClosed) {
		t.Fatalf("WriteDATALine after abort error = %v, want %v", err, errBackendBDATBodyClosed)
	}

	if !reflect.DeepEqual(sender.closeReasons, []string{testAbortReasonDataStream}) {
		t.Fatalf("close reasons = %#v, want data_stream", sender.closeReasons)
	}
}

// sendBDATPayload records backend BDAT payloads and returns scripted replies.
func (s *recordingBDATPayloadSender) sendBDATPayload(payload []byte, last bool, recipientCount int) (MessageResult, error) {
	index := len(s.chunks)

	copiedPayload := append([]byte(nil), payload...)
	s.chunks = append(s.chunks, recordedBDATPayload{
		payload:        copiedPayload,
		last:           last,
		recipientCount: recipientCount,
	})

	if s.err != nil && index == s.errAt {
		return MessageResult{}, s.err
	}

	if last {
		return s.finalResult, nil
	}

	result := MessageResult{Status: responseStatusOK}
	if s.nonFinalCalls < len(s.nonFinalResults) {
		result = s.nonFinalResults[s.nonFinalCalls]
	}

	s.nonFinalCalls++

	return result, nil
}

// close records an abort reason from backendBDATBody without exposing payload data.
func (s *recordingBDATPayloadSender) close(reasonClass string) error {
	s.closeReasons = append(s.closeReasons, reasonClass)

	return nil
}

// newRecordingBDATPayloadSender returns a sender with a successful final reply.
func newRecordingBDATPayloadSender() *recordingBDATPayloadSender {
	return &recordingBDATPayloadSender{finalResult: defaultBDATFinalResult()}
}

// defaultBDATFinalResult returns the common successful fake delivery result.
func defaultBDATFinalResult() MessageResult {
	return MessageResult{
		Statuses: []DeliveryStatus{
			{Status: responseStatusOK, Enhanced: enhancedOK, Text: backendDeliveryAcceptedText},
		},
	}
}

// assertBDATPayloads compares captured payload metadata and bytes.
func assertBDATPayloads(t *testing.T, got []recordedBDATPayload, want []recordedBDATPayload) {
	t.Helper()

	if len(got) != len(want) {
		t.Fatalf("backend BDAT payload chunks = %d, want %d", len(got), len(want))
	}

	for index := range want {
		if got[index].last != want[index].last {
			t.Fatalf("backend BDAT payload chunk %d last = %v, want %v", index, got[index].last, want[index].last)
		}

		if got[index].recipientCount != want[index].recipientCount {
			t.Fatalf("backend BDAT payload chunk %d recipient count = %d, want %d", index, got[index].recipientCount, want[index].recipientCount)
		}

		if !bytes.Equal(got[index].payload, want[index].payload) {
			t.Fatalf("backend BDAT payload chunk %d bytes = %q, want %q", index, got[index].payload, want[index].payload)
		}
	}
}

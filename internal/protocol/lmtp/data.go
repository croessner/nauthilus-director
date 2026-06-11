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
	"context"
	"errors"
	"strings"
	"time"
)

const defaultBackendBDATChunkSize = 64 * 1024

var (
	errBackendBDATBodyClosed    = errors.New("backend bdat body is closed")
	errBackendBDATBodySender    = errors.New("backend bdat payload sender is unavailable")
	errBackendBDATChunkRejected = errors.New("backend bdat chunk rejected")
	errBackendBDATInvalidChunk  = errors.New("backend bdat chunk size is invalid")
)

type dataLineWriter interface {
	WriteDATALine(line []byte) (int, error)
}

type backendBDATPayloadSender interface {
	sendBDATPayload(payload []byte, last bool, recipientCount int) (MessageResult, error)
}

type backendBDATPayloadAborter interface {
	close(reasonClass string) error
}

// handleBackendDATA streams a dot-terminated DATA body to the pinned backend.
func (s *Session) handleBackendDATA(ctx context.Context) error {
	started := time.Now()

	if s.transaction.backend == nil {
		s.recordDATAStream(ctx, lmtpObservationResultFailure, lmtpReasonBackendConnect, lmtpStatusClassUnknown, time.Since(started))

		return s.writeDeliveryStatus(unknownDeliveryStatus())
	}

	body, finish, transport, err := s.prepareBackendDATABody()
	if err != nil {
		s.recordDATAStream(ctx, lmtpObservationResultFailure, lmtpReasonDATA, statusClass(responseStatusTemporary), time.Since(started), transport)
		s.resetTransaction(ctx, "data_rejected")

		return s.writeDeliveryStatus(unknownDeliveryStatus())
	}

	if err := s.writeEnhanced(responseStatusDataContinue, enhancedOK, dataContinueText); err != nil {
		return err
	}

	if err := s.writer.Flush(); err != nil {
		s.recordDATAStream(ctx, lmtpObservationResultFailure, lmtpReasonDATA, lmtpStatusClassUnknown, time.Since(started), transport)

		return err
	}

	writeFailed, err := s.streamDATA(ctx, body)
	if err != nil {
		_ = body.Abort(ctx, "data_stream")
		s.recordDATAStream(ctx, lmtpObservationResultFailure, lmtpReasonDATA, lmtpStatusClassUnknown, time.Since(started), transport)
		s.resetTransaction(ctx, "data_stream")

		return err
	}

	if writeFailed {
		_ = body.Abort(ctx, "data_stream")
		s.recordDATAStream(ctx, lmtpObservationResultFailure, backendBodyFailureReason(transport), statusClass(responseStatusTemporary), time.Since(started), transport)

		return s.finishUnknownDelivery(ctx)
	}

	result, err := finish(ctx)
	if err != nil {
		_ = body.Abort(ctx, "data_stream")
		s.recordDATAStream(ctx, lmtpObservationResultFailure, backendBodyFailureReason(transport), statusClass(responseStatusTemporary), time.Since(started), transport)

		return s.finishUnknownDelivery(ctx)
	}

	s.recordDATAStream(ctx, deliveryResultLabel(result), deliveryReasonClass(result), deliveryResultStatusClass(result), time.Since(started), transport)

	return s.finishKnownDelivery(ctx, result)
}

// prepareBackendDATABody selects the backend body writer for a frontend DATA transaction.
func (s *Session) prepareBackendDATABody() (MessageBody, func(context.Context) (MessageResult, error), backendBodyTransport, error) {
	backendTransaction := s.transaction.backend
	recipientCount := s.transaction.recipientCount

	if backendTransaction.frontendDATABodyTransport() == backendBodyTransportBDAT {
		body := newBackendBDATBody(backendTransaction, recipientCount, defaultBackendBDATChunkSize)

		return body, body.Finish, backendBodyTransportBDAT, nil
	}

	if err := backendTransaction.beginDATA(); err != nil {
		return nil, nil, backendBodyTransportDATA, err
	}

	body := backendDATABody{transaction: backendTransaction}
	finish := func(context.Context) (MessageResult, error) {
		return backendTransaction.finishDATA(recipientCount), nil
	}

	return body, finish, backendBodyTransportDATA, nil
}

// handleBackendBDAT streams one byte-counted BDAT chunk to the pinned backend.
func (s *Session) handleBackendBDAT(ctx context.Context, chunk bdatCommand) error {
	started := time.Now()
	operation := lmtpObservationOperationBDATChunk

	if chunk.last {
		operation = lmtpObservationOperationBDATComplete
	}

	if s.transaction.backend == nil {
		s.recordBDATStream(ctx, operation, lmtpObservationResultFailure, lmtpReasonBackendConnect, lmtpStatusClassUnknown, time.Since(started))

		return s.writeDeliveryStatus(unknownDeliveryStatus())
	}

	if !s.transaction.backend.supportsChunking() {
		if err := s.discardBDATChunk(chunk.size); err != nil {
			s.recordBDATStream(ctx, operation, lmtpObservationResultFailure, lmtpReasonBDAT, lmtpStatusClassUnknown, time.Since(started))
			s.resetTransaction(ctx, "bdat_unsupported")

			return err
		}

		s.recordBDATStream(ctx, operation, lmtpObservationResultFailure, lmtpReasonBDAT, statusClass(responseStatusTemporary), time.Since(started))

		return s.finishUnknownDelivery(ctx)
	}

	result, err := s.transaction.backend.sendBDATChunk(s.reader, chunk, s.transaction.recipientCount)
	if err != nil {
		s.recordBDATStream(ctx, operation, lmtpObservationResultFailure, lmtpReasonBDAT, lmtpStatusClassUnknown, time.Since(started))

		if chunk.last {
			return s.finishUnknownDelivery(ctx)
		}

		s.resetTransaction(ctx, "bdat_stream")

		return s.writeDeliveryStatus(unknownDeliveryStatus())
	}

	if !chunk.last {
		statuses := result.Statuses
		if len(statuses) == 0 {
			statuses = []DeliveryStatus{{Status: responseStatusOK, Enhanced: enhancedOK, Text: bdatChunkAcceptedText}}
		}

		status := statuses[0]
		if status.Status != responseStatusOK {
			s.resetTransaction(ctx, "bdat_rejected")

			status = unknownDeliveryStatus()
		}

		resultLabel, reasonClass := deliveryStatusObservation(status)
		s.recordBDATStream(ctx, operation, resultLabel, reasonClass, statusClass(status.Status), time.Since(started))

		if err := s.writeDeliveryStatus(status); err != nil {
			return err
		}

		return nil
	}

	s.recordBDATStream(ctx, operation, deliveryResultLabel(result), deliveryReasonClass(result), deliveryResultStatusClass(result), time.Since(started))

	return s.finishKnownDelivery(ctx, result)
}

// finishKnownDelivery writes final statuses and clears transaction state.
func (s *Session) finishKnownDelivery(ctx context.Context, result MessageResult) error {
	s.recordDeliveryStatuses(ctx, result)
	err := s.writeMessageResult(result)
	s.closeBackendTransaction(backendCloseDeliveryComplete)
	s.closeTransactionHolds(ctx)
	s.finishTransactionObservation(ctx, deliveryResultLabel(result), deliveryReasonClass(result))
	s.transaction.reset()

	return err
}

// finishUnknownDelivery writes director temporary failures and clears transaction state.
func (s *Session) finishUnknownDelivery(ctx context.Context) error {
	result := MessageResult{Statuses: unknownDeliveryStatuses(s.transaction.recipientCount)}
	s.recordDeliveryStatuses(ctx, result)
	err := s.writeMessageResult(result)
	s.resetTransaction(ctx, "unknown_delivery")

	return err
}

type backendDATABody struct {
	transaction *backendTransaction
}

// WriteDATALine forwards one raw DATA line that is already safe for backend DATA.
func (b backendDATABody) WriteDATALine(line []byte) (int, error) {
	return b.transaction.writeDATALine(line)
}

// Write is unused for backend DATA because DATA dot-stuffing must remain intact.
func (b backendDATABody) Write(payload []byte) (int, error) {
	return b.WriteDATALine(payload)
}

// Finish is unused because backend DATA completion must emit the dot terminator first.
func (b backendDATABody) Finish(context.Context) (MessageResult, error) {
	return MessageResult{}, nil
}

// Abort closes the backend stream after incomplete DATA handling.
func (b backendDATABody) Abort(context.Context, string) error {
	if b.transaction == nil {
		return nil
	}

	return b.transaction.close("data_abort")
}

type backendBDATBody struct {
	sender         backendBDATPayloadSender
	recipientCount int
	chunkSize      int
	buffer         []byte
	closed         bool
	failed         error
}

// newBackendBDATBody creates a bounded DATA-line sink for backend BDAT payloads.
func newBackendBDATBody(sender backendBDATPayloadSender, recipientCount int, chunkSize int) *backendBDATBody {
	chunkSize = normalizeBackendBDATChunkSize(chunkSize)

	return &backendBDATBody{
		sender:         sender,
		recipientCount: recipientCount,
		chunkSize:      chunkSize,
		buffer:         make([]byte, 0, chunkSize),
	}
}

// WriteDATALine removes DATA transfer encoding and buffers raw message bytes.
func (b *backendBDATBody) WriteDATALine(line []byte) (int, error) {
	if err := b.writePayload(unescapeDataLine(line)); err != nil {
		return 0, err
	}

	return len(line), nil
}

// Write buffers raw message bytes for tests and future payload-oriented callers.
func (b *backendBDATBody) Write(payload []byte) (int, error) {
	if err := b.writePayload(payload); err != nil {
		return 0, err
	}

	return len(payload), nil
}

// Finish sends the final backend BDAT payload, including BDAT 0 LAST when empty.
func (b *backendBDATBody) Finish(context.Context) (MessageResult, error) {
	if err := b.ensureWritable(); err != nil {
		return MessageResult{}, err
	}

	result, err := b.flush(true)
	b.closed = true

	return result, err
}

// Abort marks the body closed after an incomplete DATA-to-BDAT transfer.
func (b *backendBDATBody) Abort(_ context.Context, reasonClass string) error {
	b.closed = true

	if aborter, ok := b.sender.(backendBDATPayloadAborter); ok {
		return aborter.close(reasonClass)
	}

	return nil
}

// writePayload appends bytes to the bounded buffer and flushes full chunks.
func (b *backendBDATBody) writePayload(payload []byte) error {
	if err := b.ensureWritable(); err != nil {
		return err
	}

	for len(payload) > 0 {
		remaining := b.chunkSize - len(b.buffer)
		if remaining <= 0 {
			if _, err := b.flush(false); err != nil {
				b.failed = err

				return err
			}

			remaining = b.chunkSize
		}

		if remaining > len(payload) {
			remaining = len(payload)
		}

		b.buffer = append(b.buffer, payload[:remaining]...)
		payload = payload[remaining:]

		if len(b.buffer) == b.chunkSize {
			if _, err := b.flush(false); err != nil {
				b.failed = err

				return err
			}
		}
	}

	return nil
}

// flush sends one backend BDAT payload and resets the bounded buffer.
func (b *backendBDATBody) flush(last bool) (MessageResult, error) {
	if b.sender == nil {
		return MessageResult{}, errBackendBDATBodySender
	}

	payload := b.buffer
	result, err := b.sender.sendBDATPayload(payload, last, b.recipientCount)
	b.buffer = b.buffer[:0]

	if err != nil {
		return MessageResult{}, err
	}

	if !last && !backendBDATPayloadAccepted(result) {
		if aborter, ok := b.sender.(backendBDATPayloadAborter); ok {
			_ = aborter.close("bdat_rejected")
		}

		return MessageResult{}, errBackendBDATChunkRejected
	}

	return result, nil
}

// ensureWritable rejects writes after completion or after a prior failed chunk.
func (b *backendBDATBody) ensureWritable() error {
	if b == nil {
		return errBackendBDATBodySender
	}

	if b.chunkSize <= 0 {
		return errBackendBDATInvalidChunk
	}

	if b.closed {
		return errBackendBDATBodyClosed
	}

	if b.failed != nil {
		return b.failed
	}

	return nil
}

// backendBDATPayloadAccepted reports whether an intermediate BDAT reply is safe to continue.
func backendBDATPayloadAccepted(result MessageResult) bool {
	if len(result.Statuses) > 0 {
		return result.Statuses[0].Status == responseStatusOK
	}

	status := strings.TrimSpace(result.Status)

	return status == "" || status == responseStatusOK
}

// normalizeBackendBDATChunkSize returns the deterministic default for unset callers.
func normalizeBackendBDATChunkSize(chunkSize int) int {
	if chunkSize <= 0 {
		return defaultBackendBDATChunkSize
	}

	return chunkSize
}

// backendBodyFailureReason classifies backend transport failures without raw error text.
func backendBodyFailureReason(transport backendBodyTransport) string {
	if transport == backendBodyTransportBDAT {
		return lmtpReasonBDAT
	}

	return lmtpReasonDATA
}

// writeDATALine preserves backend DATA dot-stuffing when the body supports it.
func writeDATALine(body MessageBody, line []byte) (int, error) {
	if writer, ok := body.(dataLineWriter); ok {
		return writer.WriteDATALine(line)
	}

	return body.Write(unescapeDataLine(line))
}

// unknownDeliveryStatuses returns one director temporary status per accepted recipient.
func unknownDeliveryStatuses(count int) []DeliveryStatus {
	if count <= 0 {
		return nil
	}

	statuses := make([]DeliveryStatus, 0, count)
	for range count {
		statuses = append(statuses, unknownDeliveryStatus())
	}

	return statuses
}

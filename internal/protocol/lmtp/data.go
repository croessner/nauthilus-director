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
	errMessageSizeExceeded      = errors.New("lmtp message size exceeds fixed maximum")
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

	writeFailed, err := s.streamDATA(ctx, s.messageBodyWithSizeCounter(body))
	if errors.Is(err, errMessageSizeExceeded) {
		s.recordDATAStream(ctx, lmtpObservationResultRejected, lmtpReasonSizeBodyTooLarge, statusClass(responseStatusSizeExceeded), time.Since(started), transport)

		return s.finishSizeExceededDelivery(ctx)
	}

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

	if err := s.countBDATChunk(chunk.size); err != nil {
		if drainErr := s.discardBDATChunk(chunk.size); drainErr != nil {
			s.recordBDATStream(ctx, operation, lmtpObservationResultFailure, lmtpReasonBDAT, lmtpStatusClassUnknown, time.Since(started))
			s.resetTransaction(ctx, "bdat_stream")

			return drainErr
		}

		s.recordBDATStream(ctx, operation, lmtpObservationResultRejected, lmtpReasonSizeBodyTooLarge, statusClass(responseStatusSizeExceeded), time.Since(started))

		return s.failSizeExceededBDAT(ctx, chunk.last)
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

// finishSizeExceededDelivery writes permanent size failures and clears transaction state.
func (s *Session) finishSizeExceededDelivery(ctx context.Context) error {
	result := MessageResult{Statuses: sizeExceededDeliveryStatuses(s.transaction.recipientCount)}
	s.recordDeliveryStatuses(ctx, result)
	err := s.writeMessageResult(result)
	s.resetTransaction(ctx, "size_body_too_large")

	return err
}

// failSizeExceededBDAT maps a failed frontend BDAT chunk to its required reply shape.
func (s *Session) failSizeExceededBDAT(ctx context.Context, last bool) error {
	if last {
		return s.finishSizeExceededDelivery(ctx)
	}

	status := sizeExceededDeliveryStatus()
	s.recordDeliveryStatuses(ctx, MessageResult{Statuses: []DeliveryStatus{status}})
	err := s.writeDeliveryStatus(status)
	s.resetTransaction(ctx, "size_body_too_large")

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

// sizeExceededDeliveryStatus returns the permanent status for fixed maximum violations.
func sizeExceededDeliveryStatus() DeliveryStatus {
	return DeliveryStatus{
		Status:   responseStatusSizeExceeded,
		Enhanced: enhancedSizeExceeded,
		Text:     sizeExceededText,
	}
}

// sizeExceededDeliveryStatuses repeats the size status for every accepted recipient.
func sizeExceededDeliveryStatuses(count int) []DeliveryStatus {
	if count <= 0 {
		return nil
	}

	statuses := make([]DeliveryStatus, 0, count)
	for range count {
		statuses = append(statuses, sizeExceededDeliveryStatus())
	}

	return statuses
}

type countingMessageBody struct {
	body    MessageBody
	counter *messageSizeCounter
}

// messageBodyWithSizeCounter wraps a body when this transaction has a fixed size limit.
func (s *Session) messageBodyWithSizeCounter(body MessageBody) MessageBody {
	if body == nil || s.transaction.sizeCounter == nil {
		return body
	}

	return countingMessageBody{body: body, counter: s.transaction.sizeCounter}
}

// WriteDATALine counts DATA content bytes after transfer decoding.
func (b countingMessageBody) WriteDATALine(line []byte) (int, error) {
	if err := b.counter.CountDATA(line); err != nil {
		return 0, err
	}

	return writeDATALine(b.body, line)
}

// Write counts raw payload bytes before forwarding them to the wrapped body.
func (b countingMessageBody) Write(payload []byte) (int, error) {
	if err := b.counter.CountPayload(len(payload)); err != nil {
		return 0, err
	}

	return b.body.Write(payload)
}

// Finish delegates completion without changing final delivery status semantics.
func (b countingMessageBody) Finish(ctx context.Context) (MessageResult, error) {
	return b.body.Finish(ctx)
}

// Abort delegates cleanup to the wrapped body.
func (b countingMessageBody) Abort(ctx context.Context, reasonClass string) error {
	return b.body.Abort(ctx, reasonClass)
}

type messageSizeCounter struct {
	maximum  int64
	seen     int64
	exceeded bool
}

// newMessageSizeCounter returns nil when the session has no effective fixed maximum.
func newMessageSizeCounter(maximum int64) *messageSizeCounter {
	if maximum <= 0 {
		return nil
	}

	return &messageSizeCounter{maximum: maximum}
}

// CountDATA accounts for a DATA line after removing one dot-stuffed leading dot.
func (c *messageSizeCounter) CountDATA(line []byte) error {
	return c.CountPayload(len(unescapeDataLine(line)))
}

// CountBDAT accounts for one exact frontend BDAT payload size.
func (c *messageSizeCounter) CountBDAT(size int64) error {
	return c.add(size)
}

// CountPayload accounts for already-decoded message bytes.
func (c *messageSizeCounter) CountPayload(size int) error {
	if size < 0 {
		return errMessageSizeExceeded
	}

	return c.add(int64(size))
}

// add updates the counter without overflowing and reports the first limit crossing.
func (c *messageSizeCounter) add(size int64) error {
	if c == nil || size == 0 {
		return nil
	}

	if c.exceeded || size < 0 || size > c.maximum-c.seen {
		c.exceeded = true

		return errMessageSizeExceeded
	}

	c.seen += size

	return nil
}

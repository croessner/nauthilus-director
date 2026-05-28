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
	"time"
)

type dataLineWriter interface {
	WriteDATALine(line []byte) (int, error)
}

// handleBackendDATA streams a dot-terminated DATA body to the pinned backend.
func (s *Session) handleBackendDATA(ctx context.Context) error {
	started := time.Now()

	if s.transaction.backend == nil {
		s.recordDATAStream(ctx, lmtpObservationResultFailure, lmtpReasonBackendConnect, lmtpStatusClassUnknown, time.Since(started))

		return s.writeDeliveryStatus(unknownDeliveryStatus())
	}

	if err := s.transaction.backend.beginDATA(); err != nil {
		s.recordDATAStream(ctx, lmtpObservationResultFailure, lmtpReasonDATA, statusClass(responseStatusTemporary), time.Since(started))
		s.resetTransaction(ctx, "data_rejected")

		return s.writeDeliveryStatus(unknownDeliveryStatus())
	}

	body := backendDATABody{transaction: s.transaction.backend}

	if err := s.writeEnhanced(responseStatusDataContinue, enhancedOK, dataContinueText); err != nil {
		return err
	}

	if err := s.writer.Flush(); err != nil {
		s.recordDATAStream(ctx, lmtpObservationResultFailure, lmtpReasonDATA, lmtpStatusClassUnknown, time.Since(started))

		return err
	}

	writeFailed, err := s.streamDATA(ctx, body)
	if err != nil {
		s.recordDATAStream(ctx, lmtpObservationResultFailure, lmtpReasonDATA, lmtpStatusClassUnknown, time.Since(started))
		s.resetTransaction(ctx, "data_stream")

		return err
	}

	if writeFailed {
		s.recordDATAStream(ctx, lmtpObservationResultFailure, lmtpReasonDATA, statusClass(responseStatusTemporary), time.Since(started))

		return s.finishUnknownDelivery(ctx)
	}

	result := s.transaction.backend.finishDATA(s.transaction.recipientCount)
	s.recordDATAStream(ctx, deliveryResultLabel(result), deliveryReasonClass(result), deliveryResultStatusClass(result), time.Since(started))

	return s.finishKnownDelivery(ctx, result)
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

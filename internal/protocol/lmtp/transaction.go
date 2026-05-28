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
	"fmt"
	"io"
	"strings"

	"github.com/croessner/nauthilus-director/internal/backend"
)

const (
	backendCloseDeliveryComplete = "delivery_complete"
	backendCloseRSET             = "rset"
)

type backendTransaction struct {
	connection *BackendConnection
	target     backend.Backend
}

// backendForwardingEnabled reports whether this session should deliver to real LMTP backends.
func (s *Session) backendForwardingEnabled() bool {
	return s.messageSink == nil && s.backendConnector != nil
}

// forwardRecipientToBackend prepares backend envelope state and forwards one RCPT TO.
func (s *Session) forwardRecipientToBackend(ctx context.Context, placement RecipientPlacement) (DeliveryStatus, bool) {
	if err := s.ensureBackendTransaction(ctx, placement.Backend.Backend); err != nil {
		return unknownDeliveryStatus(), false
	}

	status, err := s.transaction.backend.sendRCPT(placement.Recipient.WirePath)
	if err != nil {
		s.closeBackendTransaction("rcpt_error")

		return unknownDeliveryStatus(), false
	}

	if status.Status != responseStatusOK && s.transaction.recipientCount == 0 {
		s.closeBackendTransaction("rcpt_rejected")
	}

	return status, status.Status == responseStatusOK
}

// ensureBackendTransaction opens and authenticates the one backend transaction target.
func (s *Session) ensureBackendTransaction(ctx context.Context, target backend.Backend) error {
	if s.transaction.backend != nil {
		if !s.transaction.backend.sameTarget(target) {
			return errDifferentBackendRecipient
		}

		return nil
	}

	connection, err := s.backendConnector.Connect(ctx, target, s.backendConnectTimeout)
	if err != nil {
		return err
	}

	if err := AuthenticateBackend(connection, target); err != nil {
		_ = connection.Conn().Close()

		return err
	}

	transaction := &backendTransaction{
		connection: connection,
		target:     target,
	}

	if err := transaction.sendMAIL(s.transaction.mailFrom, s.transaction.smtpUTF8); err != nil {
		_ = transaction.close("mail_error")

		return err
	}

	s.transaction.backend = transaction

	return nil
}

// closeBackendTransaction deterministically releases any open backend stream.
func (s *Session) closeBackendTransaction(reasonClass string) {
	if s.transaction.backend == nil {
		return
	}

	_ = s.transaction.backend.close(reasonClass)
	s.transaction.backend = nil
}

// sameTarget reports whether a selected backend matches the pinned transaction target.
func (t *backendTransaction) sameTarget(target backend.Backend) bool {
	if t == nil {
		return false
	}

	return strings.TrimSpace(t.target.Identifier) == strings.TrimSpace(target.Identifier)
}

// sendMAIL forwards the frontend sender path to the selected backend.
func (t *backendTransaction) sendMAIL(wirePath string, smtpUTF8 bool) error {
	command := "MAIL FROM:" + wirePath
	if smtpUTF8 {
		command += " " + capabilitySMTPUTF8
	}

	response, err := t.connection.commandResponse(command)
	if err != nil {
		return err
	}

	if !response.statusOK(responseStatusOK) {
		return fmt.Errorf("%w: backend rejected mail envelope", ErrBackendProtocol)
	}

	return nil
}

// sendRCPT forwards one accepted-candidate recipient and returns a safe status.
func (t *backendTransaction) sendRCPT(wirePath string) (DeliveryStatus, error) {
	response, err := t.connection.commandResponse("RCPT TO:" + wirePath)
	if err != nil {
		return DeliveryStatus{}, err
	}

	return deliveryStatusFromBackend(response, backendReplyContextRecipient), nil
}

// beginDATA enters backend DATA mode before frontend data bytes are consumed.
func (t *backendTransaction) beginDATA() error {
	response, err := t.connection.commandResponse(commandDATA)
	if err != nil {
		return err
	}

	if !response.statusOK(responseStatusDataContinue) {
		return fmt.Errorf("%w: backend rejected data", ErrBackendProtocol)
	}

	return nil
}

// writeDATALine forwards one already-dot-stuffed DATA payload line to the backend.
func (t *backendTransaction) writeDATALine(line []byte) (int, error) {
	return t.connection.writer.Write(line)
}

// finishDATA terminates backend DATA and reads one final status per accepted recipient.
func (t *backendTransaction) finishDATA(recipientCount int) MessageResult {
	if _, err := t.connection.writer.WriteString(".\r\n"); err != nil {
		return MessageResult{Statuses: unknownDeliveryStatuses(recipientCount)}
	}

	if err := t.connection.writer.Flush(); err != nil {
		return MessageResult{Statuses: unknownDeliveryStatuses(recipientCount)}
	}

	return t.readFinalStatuses(recipientCount)
}

// sendBDATChunk forwards one byte-counted chunk and reads the expected backend reply.
func (t *backendTransaction) sendBDATChunk(reader io.Reader, chunk bdatCommand, recipientCount int) (MessageResult, error) {
	command := fmt.Sprintf("%s %d", commandBDAT, chunk.size)
	if chunk.last {
		command += " LAST"
	}

	if _, err := fmt.Fprintf(t.connection.writer, "%s\r\n", command); err != nil {
		return MessageResult{}, err
	}

	if chunk.size > 0 {
		written, err := io.CopyN(t.connection.writer, reader, chunk.size)
		if err != nil {
			return MessageResult{}, err
		}

		if written != chunk.size {
			return MessageResult{}, io.ErrUnexpectedEOF
		}
	}

	if err := t.connection.writer.Flush(); err != nil {
		return MessageResult{}, err
	}

	if !chunk.last {
		response, err := t.connection.readResponse()
		if err != nil {
			return MessageResult{}, err
		}

		return MessageResult{Statuses: []DeliveryStatus{deliveryStatusFromBackend(response, backendReplyContextBDAT)}}, nil
	}

	return t.readFinalStatuses(recipientCount), nil
}

// readFinalStatuses reads backend final replies without desynchronizing recipient order.
func (t *backendTransaction) readFinalStatuses(recipientCount int) MessageResult {
	statuses := make([]DeliveryStatus, 0, recipientCount)
	for len(statuses) < recipientCount {
		response, err := t.connection.readResponse()
		if err != nil {
			statuses = append(statuses, unknownDeliveryStatuses(recipientCount-len(statuses))...)

			return MessageResult{Statuses: statuses}
		}

		statuses = append(statuses, deliveryStatusFromBackend(response, backendReplyContextFinal))
	}

	return MessageResult{Statuses: statuses}
}

// close resets or politely closes the backend stream, then releases the socket.
func (t *backendTransaction) close(reasonClass string) error {
	if t == nil || t.connection == nil || t.connection.Conn() == nil {
		return nil
	}

	switch reasonClass {
	case backendCloseRSET:
		_ = t.connection.expectStatus(commandRSET, responseStatusOK)
	}

	return t.connection.Conn().Close()
}

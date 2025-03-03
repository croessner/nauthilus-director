package lmtp

import (
	"bufio"
	"fmt"
	"log/slog"
	"net"
	"net/textproto"
	"strings"

	"github.com/croessner/nauthilus-director/interfaces"
	"github.com/croessner/nauthilus-director/log"
)

// TODO: Work in progress... Simple tests for LMTP

type State uint

const (
	StateWaitingMailFrom State = iota
	StateWaitingRcptTo
	StateReceivingData
)

func Handler(proxy iface.Proxy, rawClientConn net.Conn) {
	logger := log.GetLogger(proxy.GetContext())

	defer func(rawClientConn net.Conn) {
		_ = rawClientConn.Close()
	}(rawClientConn)

	reader := bufio.NewReader(rawClientConn)
	tp := textproto.NewReader(reader)

	// Initial greeting to the LMTP client
	_, _ = fmt.Fprintf(rawClientConn, "220 LMTP Server Ready\r\n")

	// Read and process LHLO command
	cmd, err := tp.ReadLine()
	if err != nil {
		logger.Error("Error reading LHLO:", err)

		return
	}
	if !strings.HasPrefix(cmd, "LHLO") {
		// If the client does not send LHLO, we return a syntax error
		_, _ = fmt.Fprintf(rawClientConn, "500 5.5.1 Syntax error, LHLO expected\r\n")

		return
	}

	// Announce PIPELINING and other supported features
	_, _ = fmt.Fprintf(rawClientConn, "250-PIPELINING\r\n250 SIZE 10485760\r\n")

	// Hand over to the main session handling logic
	handleSession(tp, rawClientConn, logger)
}

func handleSession(tp *textproto.Reader, rawClientConn net.Conn, logger *slog.Logger) {
	state := StateWaitingMailFrom
	pipeliningDetected := false

	cmdQueue := make([]string, 0)
	recipients := make([]string, 0) // List of recipients for this session

CommandQueueLoop:
	for {
		// Read the next command from the client
		cmd, err := tp.ReadLine()
		if err != nil {
			logger.Error("Error reading command", slog.String(log.KeyError, err.Error()))

			break
		}

		// Add the command to the command queue for processing (this will detect PIPELINING)
		cmdQueue = append(cmdQueue, cmd)
		if len(cmdQueue) > 1 {
			// If there is more than one command in the queue, PIPELINING is detected
			pipeliningDetected = true
		}

		// Process all commands in the queue
		for len(cmdQueue) > 0 {
			currentCmd := cmdQueue[0] // Get the first command in the queue
			cmdQueue = cmdQueue[1:]   // Remove it from the queue

			// Handle NOOP and RSET commands regardless of the state
			if strings.EqualFold(currentCmd, "NOOP") {
				// Respond to NOOP with a success message
				_, _ = fmt.Fprintf(rawClientConn, "250 OK\r\n")

				continue
			} else if strings.EqualFold(currentCmd, "RSET") {
				// Reset the session state
				state = StateWaitingMailFrom
				recipients = []string{} // Clear the recipient list

				_, _ = fmt.Fprintf(rawClientConn, "250 OK\r\n")

				continue
			}

			// Handle state-specific commands
			switch state {
			case StateWaitingMailFrom:
				if strings.HasPrefix(currentCmd, "MAIL FROM:") {
					// Process MAIL FROM and move to the next state
					_, _ = fmt.Fprintf(rawClientConn, "250 OK\r\n")
					state = StateWaitingRcptTo
					recipients = []string{} // Clear any previous recipients for a fresh MAIL FROM
				} else if strings.HasPrefix(currentCmd, "QUIT") {
					// If the client sends QUIT, close the session gracefully
					_, _ = fmt.Fprintf(rawClientConn, "221 Bye\r\n")

					break CommandQueueLoop
				} else {
					// If the command is invalid, return an error and terminate the session
					_, _ = fmt.Fprintf(rawClientConn, "500 5.5.1 Syntax error, MAIL FROM or QUIT expected\r\n")

					return
				}

			case StateWaitingRcptTo:
				if strings.HasPrefix(currentCmd, "RCPT TO:") {
					// Extract the recipient from the command (basic validation could be added here)
					recipient := strings.TrimSpace(currentCmd[8:])
					recipients = append(recipients, recipient) // Add recipient to the list

					_, _ = fmt.Fprintf(rawClientConn, "250 OK\r\n") // Acknowledge the recipient
				} else if strings.EqualFold(currentCmd, "DATA") {
					// DATA command is valid only if there are recipients
					if len(recipients) == 0 {
						_, _ = fmt.Fprintf(rawClientConn, "503 5.5.2 Bad sequence of commands: RCPT TO required before DATA\r\n")
					} else {
						// Transition to receiving email data
						_, _ = fmt.Fprintf(rawClientConn, "354 Start mail input\r\n")
						state = StateReceivingData
					}
				} else if strings.HasPrefix(currentCmd, "QUIT") {
					// If the client sends QUIT, close the session gracefully
					_, _ = fmt.Fprintf(rawClientConn, "221 Bye\r\n")

					break CommandQueueLoop
				} else {
					// If the command is invalid, return an error and terminate the session
					_, _ = fmt.Fprintf(rawClientConn, "500 5.5.1 Syntax error, RCPT TO, DATA or QUIT expected\r\n")

					return
				}

			case StateReceivingData:
				if currentCmd == "." {
					queueID := "TODO" // Placeholder for Queue-ID logic

					// End of mail data input
					_, _ = fmt.Fprintf(rawClientConn, "250 2.0.0 OK: queued as %s\r\n", queueID)

					logger.Debug("Email processed for recipients", slog.String("recipients", strings.Join(recipients, ", ")))

					state = StateWaitingMailFrom // Ready for a new transaction
				} else {
					// Process received email data (e.g., store it, log it, etc.)
					logger.Debug("Received email data", slog.String("command", currentCmd))
				}
			}
		}
	}

	// Log whether PIPELINING was detected during the session
	if pipeliningDetected {
		logger.Info("PIPELINING detected: Client sent multiple commands without waiting")
	} else {
		logger.Info("No PIPELINING: Client processed commands sequentially")
	}
}

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

package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

const proxyBufferSize = 32 * 1024

// LeaseLifecycle receives active-session heartbeat and close callbacks from proxy mode.
type LeaseLifecycle interface {
	Heartbeat(ctx context.Context) error
	Close(ctx context.Context) error
}

// Runner executes one transparent proxy lifecycle.
type Runner interface {
	Run(ctx context.Context, config PipeConfig) (Result, error)
}

// PipeConfig contains one authenticated frontend/backend stream pair.
type PipeConfig struct {
	Frontend          net.Conn
	Backend           net.Conn
	BufferedToBackend []byte
	BufferedToClient  []byte
	IdleTimeout       time.Duration
	HeartbeatInterval time.Duration
	Lease             LeaseLifecycle
}

// Pipe copies bytes until one stream closes, times out or the context shuts down.
type Pipe struct{}

// NewPipe creates the production transparent proxy runner.
func NewPipe() *Pipe {
	return &Pipe{}
}

// Run executes transparent bidirectional proxy mode and always attempts lease close.
func (p *Pipe) Run(ctx context.Context, config PipeConfig) (Result, error) {
	if err := validatePipeConfig(config); err != nil {
		return Result{Class: ResultStateFailed, Err: err}, err
	}

	if ctx == nil {
		ctx = context.Background()
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	deadlines := newDeadlineController(config.Frontend, config.Backend, config.IdleTimeout)

	result := Result{}
	if err := deadlines.touch(); err != nil {
		result.Class = ResultStateFailed
		result.Err = err

		return finishProxyResult(result, config)
	}

	if ok := writeInitialBuffers(&result, config, deadlines); !ok {
		return finishProxyResult(result, config)
	}

	events := make(chan pipeEvent, 3)

	var copyWG sync.WaitGroup

	copyWG.Add(2)

	go proxyCopy(&copyWG, events, DirectionClientToBackend, config.Backend, config.Frontend, deadlines)
	go proxyCopy(&copyWG, events, DirectionBackendToClient, config.Frontend, config.Backend, deadlines)

	heartbeatDone := startHeartbeat(runCtx, events, config)

	first := waitForProxyEvent(runCtx, events)
	result.Accounted.add(first.direction, first.bytes)
	result.Class = first.class
	result.Err = first.err

	cancel()
	closeBoth(config.Frontend, config.Backend)
	copyWG.Wait()
	waitHeartbeat(heartbeatDone)

	for len(events) > 0 {
		event := <-events
		result.Accounted.add(event.direction, event.bytes)

		if result.Err == nil && event.err != nil {
			result.Err = event.err
		}
	}

	return finishProxyResult(result, config)
}

// validatePipeConfig rejects incomplete stream pairs before proxy mode starts.
func validatePipeConfig(config PipeConfig) error {
	if config.Frontend == nil {
		return errors.New("proxy: frontend connection required")
	}

	if config.Backend == nil {
		return errors.New("proxy: backend connection required")
	}

	return nil
}

// writeInitialBuffers sends buffered bytes before either live copy goroutine starts.
func writeInitialBuffers(result *Result, config PipeConfig, deadlines *deadlineController) bool {
	if !writeInitial(result, DirectionClientToBackend, config.Backend, config.BufferedToBackend, deadlines) {
		closeBoth(config.Frontend, config.Backend)

		return false
	}

	if !writeInitial(result, DirectionBackendToClient, config.Frontend, config.BufferedToClient, deadlines) {
		closeBoth(config.Frontend, config.Backend)

		return false
	}

	return true
}

// writeInitial writes buffered handoff bytes to the destination stream.
func writeInitial(
	result *Result,
	direction string,
	destination net.Conn,
	buffered []byte,
	deadlines *deadlineController,
) bool {
	if len(buffered) == 0 {
		return true
	}

	written, err := writeAll(destination, buffered)
	result.Accounted.add(direction, int64(written))

	if err != nil {
		result.Class = classifyWriteError(direction, err)
		result.Err = err

		return false
	}

	if err := deadlines.touch(); err != nil {
		result.Class = ResultStateFailed
		result.Err = err

		return false
	}

	return true
}

// proxyCopy copies one direction and sends a single completion event.
func proxyCopy(
	wg *sync.WaitGroup,
	events chan<- pipeEvent,
	direction string,
	destination net.Conn,
	source net.Conn,
	deadlines *deadlineController,
) {
	defer wg.Done()

	buffer := make([]byte, proxyBufferSize)

	var total int64

	for {
		read, readErr := source.Read(buffer)
		if read > 0 {
			written, writeErr := writeAll(destination, buffer[:read])

			total += int64(written)

			if writeErr != nil {
				events <- pipeEvent{
					direction: direction,
					bytes:     total,
					class:     classifyWriteError(direction, writeErr),
					err:       writeErr,
				}

				return
			}

			if err := deadlines.touch(); err != nil {
				if isClosedError(err) {
					continue
				}

				events <- pipeEvent{
					direction: direction,
					bytes:     total,
					class:     ResultStateFailed,
					err:       err,
				}

				return
			}
		}

		if readErr != nil {
			events <- pipeEvent{
				direction: direction,
				bytes:     total,
				class:     classifyReadError(direction, readErr),
				err:       resultError(readErr),
			}

			return
		}
	}
}

// writeAll writes the whole buffer or returns the partial byte count and error.
func writeAll(writer io.Writer, data []byte) (int, error) {
	var total int
	for total < len(data) {
		written, err := writer.Write(data[total:])

		total += written

		if err != nil {
			return total, err
		}

		if written == 0 {
			return total, io.ErrShortWrite
		}
	}

	return total, nil
}

// pipeEvent carries one proxy lifecycle or copy completion event.
type pipeEvent struct {
	direction string
	bytes     int64
	class     string
	err       error
}

// waitForProxyEvent returns context shutdown if it wins the race with stream completion.
func waitForProxyEvent(ctx context.Context, events <-chan pipeEvent) pipeEvent {
	select {
	case event := <-events:
		return event
	case <-ctx.Done():
		return pipeEvent{class: ResultShutdown, err: ctx.Err()}
	}
}

// startHeartbeat starts the active session heartbeat loop when configured.
func startHeartbeat(ctx context.Context, events chan<- pipeEvent, config PipeConfig) <-chan struct{} {
	done := make(chan struct{})
	if config.Lease == nil || config.HeartbeatInterval <= 0 {
		close(done)

		return done
	}

	go func() {
		defer close(done)

		ticker := time.NewTicker(config.HeartbeatInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := config.Lease.Heartbeat(ctx); err != nil {
					events <- pipeEvent{class: ResultStateFailed, err: err}

					return
				}
			}
		}
	}()

	return done
}

// waitHeartbeat waits until the heartbeat loop has observed cancellation.
func waitHeartbeat(done <-chan struct{}) {
	<-done
}

// finishProxyResult closes the lease and joins any cleanup error into the result.
func finishProxyResult(result Result, config PipeConfig) (Result, error) {
	if result.Class == "" {
		result.Class = ResultClientClosed
	}

	if config.Lease != nil {
		if err := config.Lease.Close(context.Background()); err != nil {
			result.CloseError = err
			result.Err = errors.Join(result.Err, err)
			result.Class = ResultStateFailed
		}
	}

	return result, result.Err
}

// closeBoth closes both sides of a proxy stream pair.
func closeBoth(frontend net.Conn, backend net.Conn) {
	_ = frontend.Close()
	_ = backend.Close()
}

// classifyReadError turns a read-side error into an allowed result class.
func classifyReadError(direction string, err error) string {
	if isTimeout(err) {
		return ResultTimeout
	}

	if direction == DirectionClientToBackend {
		return ResultClientClosed
	}

	return ResultBackendClosed
}

// classifyWriteError turns a write-side error into an allowed result class.
func classifyWriteError(direction string, err error) string {
	if isTimeout(err) {
		return ResultTimeout
	}

	if direction == DirectionClientToBackend {
		return ResultBackendClosed
	}

	return ResultClientClosed
}

// isTimeout reports whether an error is a network timeout.
func isTimeout(err error) bool {
	var netErr net.Error

	return errors.As(err, &netErr) && netErr.Timeout()
}

// isClosedError reports local close races that occur while the other copy direction is ending.
func isClosedError(err error) bool {
	return errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe)
}

// resultError suppresses ordinary EOF while preserving actionable failures.
func resultError(err error) error {
	if errors.Is(err, io.EOF) {
		return nil
	}

	return err
}

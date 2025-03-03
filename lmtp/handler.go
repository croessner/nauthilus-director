package lmtp

import (
	"bufio"
	"fmt"
	"net"
	"net/textproto"
	"time"

	"github.com/croessner/nauthilus-director/interfaces"
	"github.com/croessner/nauthilus-director/log"
)

func Handler(proxy iface.Proxy, rawClientConn net.Conn) {
	logger := log.GetLogger(proxy.GetContext())

	defer rawClientConn.Close()

	reader := bufio.NewReader(rawClientConn)
	tp := textproto.NewReader(reader)

	// Greeting
	fmt.Fprintf(rawClientConn, "220 LMTP Server Ready\r\n")

	// LHLO
	_, _ = tp.ReadLine()
	fmt.Fprintf(rawClientConn, "250-PIPELINING\r\n250 SIZE 10485760\r\n")

	// MAIL FROM
	_, err := tp.ReadLine()
	if err != nil {
		logger.Error("Error while reading MAIL FROM:", err.Error())
		return
	}
	fmt.Fprintf(rawClientConn, "250 OK\r\n")

	// **Lookahead to gather PIPELINING**
	rawClientConn.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	peek, err := reader.Peek(1)

	pipelining := err == nil && len(peek) > 0

	if !pipelining {
		rawClientConn.SetReadDeadline(time.Time{})
	}

	// RCPT TO
	_, err = tp.ReadLine()
	if err != nil {
		logger.Error("Error while reading RCPT TO:", err.Error())

		return
	}

	fmt.Fprintf(rawClientConn, "250 OK\r\n")

	// Falls der Client PIPELINING nutzt, müssen wir weiterpuffern
	if pipelining {
		logger.Debug("Client uses PIPELINING")
	} else {
		logger.Debug("Client wats for answers (no PIPELINING)")
	}

	// DATA lesen (falls nötig)
	dataCmd, err := tp.ReadLine()
	if err != nil {
		logger.Error("Error while reading DATA:", err.Error())

		return
	}

	if dataCmd == "DATA" {
		fmt.Fprintf(rawClientConn, "354 Start mail input\r\n")

		_, _ = tp.ReadLine()

		fmt.Fprintf(rawClientConn, "250 OK\r\n")
	}
}

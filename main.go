package main

import (
	"context"
	"fmt"
	"os"

	"github.com/croessner/nauthilus-director/auth"
	"github.com/croessner/nauthilus-director/imap"
)

func main() {
	authenticator := &auth.MockAuthenticator{} // TODO: Replace with Nauthilus authenticator

	proxy := imap.NewProxy(context.Background(), ":10143", authenticator) // Proxy lauscht auf Port 10143

	if proxy == nil {
		fmt.Println("Error creating proxy")

		os.Exit(1)
	}

	if err := proxy.Start(); err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
}

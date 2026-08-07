// Command x402stranger-client pays for examples/x402stranger's resource with
// nothing but a raw private key: no ATXP account, no OAuth, no prior
// relationship with the merchant at all. This is the actual
// stranger-to-stranger case chit's self-custodial signing was built for.
//
// Usage:
//
//	X402_PRIVATE_KEY=<hex-encoded secp256k1 key, funded with a little USDC> \
//	go run ./examples/x402stranger/client http://127.0.0.1:8767/pay
package main

import (
	"io"
	"log"
	"os"

	atxp "github.com/justinstimatze/chit"
	"github.com/justinstimatze/chit/x402signer"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: x402stranger-client <resource-url>")
	}
	resourceURL := os.Args[1]

	privHex := os.Getenv("X402_PRIVATE_KEY")
	if privHex == "" {
		log.Fatal("X402_PRIVATE_KEY not set")
	}
	network := os.Getenv("X402_NETWORK")
	if network == "" {
		network = "eip155:8453" // Base mainnet
	}

	acct, err := x402signer.NewFromPrivateKeyHex(privHex, network)
	if err != nil {
		log.Fatalf("NewFromPrivateKeyHex: %v", err)
	}
	log.Printf("payer address: %s (no ATXP account, this is the only identity)", acct.Address())

	c, err := atxp.NewWithAccount(atxp.Config{}, acct)
	if err != nil {
		log.Fatalf("NewWithAccount: %v", err)
	}

	resp, err := c.HTTPClient().Get(resourceURL)
	if err != nil {
		log.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		log.Fatalf("payment failed: status=%d body=%q", resp.StatusCode, body)
	}
	log.Printf("paid successfully: %s", body)
}

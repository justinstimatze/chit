// Command x402stranger is a minimal x402 merchant that proves the actual
// promise of self-custodial x402 payments: a caller with no ATXP account, no
// OAuth relationship, and no prior interaction with this merchant can still
// pay for a resource and receive it. Live-verified end to end against
// production ATXP infrastructure on Base mainnet, confirmed on-chain (see
// docs/PROTOCOL.md's payment-modes table, case 6).
//
// The merchant does need its own ATXP account, to register and settle, but
// the payer needs nothing beyond a raw private key: see
// examples/x402stranger/client.
//
// Usage:
//
//	ATXP_CONNECTION=<merchant connection string> \
//	DEST_ADDRESS=<merchant payout address, same chain as CHAIN> \
//	CHAIN=base \
//	go run ./examples/x402stranger
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"

	"github.com/justinstimatze/chit/server"
)

func main() {
	conn := os.Getenv("ATXP_CONNECTION")
	if conn == "" {
		log.Fatal("ATXP_CONNECTION not set (merchant's own connection string)")
	}
	destAddr := os.Getenv("DEST_ADDRESS")
	if destAddr == "" {
		log.Fatal("DEST_ADDRESS not set (merchant payout address)")
	}
	chain := os.Getenv("CHAIN")
	if chain == "" {
		chain = "base"
	}
	u, err := url.Parse(conn)
	if err != nil {
		log.Fatalf("parse ATXP_CONNECTION: %v", err)
	}
	token := u.Query().Get("connection_token")
	if token == "" {
		log.Fatal("ATXP_CONNECTION missing connection_token")
	}

	// merchantID doubles as the destination and as the nominal sourceAccountId
	// on /payment-request: that field is never checked against the actual
	// payer (see docs/PROTOCOL.md's fraud-block bypass note), so there is no
	// real payer identity to supply here, and no reason to invent one.
	merchantID := chain + ":" + destAddr

	m, err := server.New(server.Config{
		Destination:     server.StaticDestination{ID: merchantID},
		ConnectionToken: token,
		PayeeName:       "chit x402stranger example",
		Logger:          server.NewStdLogger(),
	})
	if err != nil {
		log.Fatalf("server.New: %v", err)
	}

	price, err := server.ParseAmount("0.01")
	if err != nil {
		log.Fatalf("ParseAmount: %v", err)
	}

	resourceURL := "http://127.0.0.1:8767/pay"

	// A session's settle call needs the same X402PaymentRequirements that was
	// advertised in the 402 challenge to build a valid settle body, chit has
	// no exported way to rebuild it standalone. There is no OAuth-derived
	// caller id to key this by (that's the whole point of this example), so
	// it's keyed by remote address instead, good enough to keep two
	// concurrent strangers' challenges from clobbering each other.
	var challengeMu sync.Mutex
	lastChallenge := map[string]server.X402PaymentRequirements{}
	lastPaymentID := map[string]string{}

	http.HandleFunc("/pay", func(w http.ResponseWriter, r *http.Request) {
		// User: merchantID is a placeholder. There is no OAuth-authenticated
		// caller for a genuine x402 stranger. This makes every first call a
		// source==destination self-charge, which server/live_test.go's
		// TestLiveSettlesRealPayment notes the AS "may treat ... specially":
		// in practice, /charge has been observed to report an unauthenticated
		// self-charge as already-settled shortly after this same merchant
		// account was involved in a real settlement, rather than reliably
		// declining with 402. RequirePayment can't distinguish that from a
		// legitimate pre-authorized pull, so it isn't something chit's gate
		// can work around; a merchant relying on this example's shape should
		// know call-1 isn't guaranteed to always yield a fresh challenge.
		pr := server.PaymentRequest{Price: price, User: merchantID, Resource: resourceURL}

		var session *server.PaymentSession
		if detected := server.DetectProtocol(r.Header); detected != nil {
			// The credential's own signer is the only identity here that is
			// cryptographically real, unlike sourceAccountId above. A real
			// merchant wanting its own rate limits, spend caps, or blocklists
			// should gate on this address, not on anything ATXP reports.
			if payerAddr, err := server.ExtractX402PayerAddress(detected.Credential); err == nil {
				log.Printf("payer address: %s", payerAddr)
			}

			challengeMu.Lock()
			reqs, ok := lastChallenge[r.RemoteAddr]
			paymentID := lastPaymentID[r.RemoteAddr]
			challengeMu.Unlock()
			sctx := server.SettlementContext{SourceAccountID: merchantID, DestinationAccountID: merchantID, PaymentRequestID: paymentID}
			if ok {
				sctx.PaymentRequirements = &reqs
			}
			session = m.OpenPaymentSession(*detected, sctx)
			pr.Session = session
		}

		ch, err := m.RequirePayment(r.Context(), pr)
		if err != nil {
			log.Printf("RequirePayment error: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if ch != nil {
			log.Printf("payment required, issuing challenge paymentRequestId=%v", ch.Data["paymentRequestId"])
			challengeMu.Lock()
			lastChallenge[r.RemoteAddr] = ch.X402
			lastPaymentID[r.RemoteAddr] = fmt.Sprint(ch.Data["paymentRequestId"])
			challengeMu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusPaymentRequired)
			_ = json.NewEncoder(w).Encode(ch.Data)
			return
		}

		if session != nil {
			// CloseSession itself fails closed on underpayment (a
			// *server.UnderpaymentError), not just on network/settle
			// failures: the x402 "exact" scheme settles for exactly the
			// signed authorization.value, which a modified client could set
			// lower than the accepted.amount it self-reports elsewhere in the
			// same credential. A nil error here really does mean paid in
			// full, for at least what was charged.
			if err := m.CloseSession(context.Background(), session); err != nil {
				log.Printf("CloseSession error: %v", err)
				http.Error(w, "settlement failed: "+err.Error(), http.StatusPaymentRequired)
				return
			}
			log.Printf("session closed/settled, spent=%s", session.Spent().String())
		}

		log.Println("payment settled, serving request")
		if _, err := w.Write([]byte("pong")); err != nil {
			log.Printf("write response: %v", err)
		}
	})

	ln, err := net.Listen("tcp", "127.0.0.1:8767")
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("x402stranger merchant listening on %s", ln.Addr())
	// Binds to 127.0.0.1 only, for local testing. A real deployment reachable
	// by strangers needs a reverse proxy/tunnel terminating TLS in front of
	// this, same as examples/paidmcp.
	log.Fatal(http.Serve(ln, nil))
}

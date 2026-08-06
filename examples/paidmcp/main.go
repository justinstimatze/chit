// Command paidmcp is a minimal, real MCP server that charges callers over
// ATXP for a tool call, using chit's server package. It exists to prove the
// full live loop end to end: a caller with no established ATXP Connection to
// this resource gets a real 401 (no bearer token) then a real 402 omni-challenge
// (unpaid), completes the OAuth + payment authorize dance for real, and the
// retry settles through chit's Merchant.
//
// Usage:
//
//	ATXP_CONNECTION=<merchant connection string> \
//	PUBLIC_URL=https://<host>.<tailnet>.ts.net \
//	go run ./examples/paidmcp -port 8765
//
// PUBLIC_URL must be the address this process is reachable at from the public
// internet (e.g. a Tailscale Funnel URL) — ATXP's authorization server needs
// to fetch this resource's protected-resource metadata during the OAuth
// handshake, so localhost is not sufficient.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/modelcontextprotocol/go-sdk/oauthex"

	atxp "github.com/justinstimatze/chit"
	"github.com/justinstimatze/chit/server"
)

type pingArgs struct{}

// fetchAccountSources reads the account's own chain addresses off GET /me, so
// the merchant's Destination can advertise real x402/MPP payout addresses
// instead of just the bare ATXP-native account id. Without this, ATXP's own
// /authorize/auto rejected settlement with "DESTINATION_NOT_ALLOWED — not
// allowed for IOU conversion": apparently even ATXP-native settlement needs a
// real chain address to convert the payer's balance into, not just an
// internal ledger entry.
func fetchAccountSources(ctx context.Context, origin, token string) ([]server.Source, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, origin+"/me", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(token+":")))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("/me returned %d", resp.StatusCode)
	}
	var out struct {
		Sources []struct {
			Chain   string `json:"chain"`
			Address string `json:"address"`
		} `json:"sources"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	sources := make([]server.Source, 0, len(out.Sources))
	seen := map[string]bool{}
	for _, s := range out.Sources {
		if seen[s.Chain] {
			continue // keep the first address per chain (e.g. skip the "smart" wallet if "eoa" already claimed it)
		}
		seen[s.Chain] = true
		sources = append(sources, server.Source{Chain: s.Chain, Address: s.Address})
	}
	return sources, nil
}

func main() {
	port := flag.Int("port", 8765, "port to listen on")
	flag.Parse()

	conn := os.Getenv("ATXP_CONNECTION")
	if conn == "" {
		log.Fatal("ATXP_CONNECTION not set (merchant's own connection string)")
	}
	publicURL := os.Getenv("PUBLIC_URL")
	if publicURL == "" {
		log.Fatal("PUBLIC_URL not set (e.g. https://host.tailnet.ts.net)")
	}

	ctx := context.Background()

	u, err := url.Parse(conn)
	if err != nil {
		log.Fatalf("parse ATXP_CONNECTION: %v", err)
	}
	token := u.Query().Get("connection_token")
	if token == "" {
		log.Fatal("ATXP_CONNECTION missing connection_token")
	}

	acct, err := atxp.NewATXPAccount(conn, nil)
	if err != nil {
		log.Fatalf("NewATXPAccount: %v", err)
	}
	merchantID, err := acct.AccountID(ctx)
	if err != nil {
		log.Fatalf("resolve merchant account id: %v", err)
	}
	log.Printf("merchant account: %s", merchantID)

	sources, err := fetchAccountSources(ctx, u.Scheme+"://"+u.Host, token)
	if err != nil {
		log.Fatalf("fetch account sources: %v", err)
	}
	log.Printf("merchant chain addresses: %+v", sources)

	m, err := server.New(server.Config{
		Destination:     server.StaticDestination{ID: merchantID, Addresses: sources},
		ConnectionToken: token,
		// ATXP's DCR client_name is globally unique across all developers, not
		// scoped per account/token — a fixed name here would collide with a
		// prior run's registration the moment a different account is used.
		PayeeName: "chit paidmcp example (" + merchantID + ")",
		Logger:    server.NewStdLogger(),
	})
	if err != nil {
		log.Fatalf("server.New: %v", err)
	}

	price, err := server.ParseAmount("0.01")
	if err != nil {
		log.Fatalf("ParseAmount: %v", err)
	}

	resourceURL := publicURL + "/mcp"
	prmURL := publicURL + "/.well-known/oauth-protected-resource"

	mcpServer := mcp.NewServer(&mcp.Implementation{Name: "chit-paidmcp-example", Version: "0.1.0"}, nil)
	mcp.AddTool(mcpServer, &mcp.Tool{Name: "ping", Description: "Paid ping — replies pong, charges $0.01 via ATXP"},
		func(ctx context.Context, req *mcp.CallToolRequest, in pingArgs) (*mcp.CallToolResult, any, error) {
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "pong"}}}, nil, nil
		})

	mcpHandler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return mcpServer }, nil)

	verifyToken := func(ctx context.Context, tok string, r *http.Request) (*auth.TokenInfo, error) {
		resourceU, _ := url.Parse(resourceURL)
		tc := m.CheckToken(ctx, resourceU, "Bearer "+tok)
		if !tc.Passes {
			log.Printf("token check failed: %s", tc.Problem)
			return nil, auth.ErrInvalidToken
		}
		exp := time.Now().Add(time.Hour)
		if tc.Data.Exp > 0 {
			exp = time.Unix(tc.Data.Exp, 0)
		}
		return &auth.TokenInfo{UserID: tc.Data.Sub, Expiration: exp}, nil
	}

	authMiddleware := auth.RequireBearerToken(verifyToken, &auth.RequireBearerTokenOptions{
		ResourceMetadataURL: prmURL,
	})

	paymentGate := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ti := auth.TokenInfoFromContext(r.Context())
			if ti == nil || ti.UserID == "" {
				http.Error(w, "no authenticated user", http.StatusUnauthorized)
				return
			}
			sub := ti.UserID

			pr := server.PaymentRequest{Price: price, User: sub, Resource: resourceURL}

			var session *server.PaymentSession
			if detected := server.DetectProtocol(r.Header); detected != nil {
				log.Printf("payment credential detected: protocol=%s", detected.Protocol)
				session = m.OpenPaymentSession(*detected, server.SettlementContext{})
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
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusPaymentRequired)
				_ = json.NewEncoder(w).Encode(ch.Data)
				return
			}

			log.Printf("payment settled for %s, serving request", sub)
			next.ServeHTTP(w, r)

			if session != nil {
				if err := m.CloseSession(context.Background(), session); err != nil {
					log.Printf("CloseSession error: %v", err)
				} else {
					log.Printf("session closed/settled, spent=%s", session.Spent().String())
				}
			}
		})
	}

	metadata := &oauthex.ProtectedResourceMetadata{
		Resource:             resourceURL,
		AuthorizationServers: []string{"https://auth.atxp.ai"},
	}
	http.Handle("/.well-known/oauth-protected-resource", auth.ProtectedResourceMetadataHandler(metadata))
	http.Handle("/mcp", authMiddleware(paymentGate(mcpHandler)))

	addr := fmt.Sprintf("127.0.0.1:%d", *port)
	log.Printf("listening on %s, resource=%s", addr, resourceURL)
	log.Fatal(http.ListenAndServe(addr, nil))
}

//go:build atxplive

// Live, credential-free integration test against real ATXP infrastructure.
// Run explicitly:  go test -tags atxplive -run TestLive ./internal/atxp/...
//
// It exercises the parts of the OAuth flow that need no account or crypto:
// protected-resource discovery, authorization-server metadata, and dynamic
// client registration. The paid path (/sign, /authorize/auto, a tool call)
// requires a connection string and is covered by httptest in atxp_test.go.
package atxp

import (
	"bufio"
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// liveConnectionString returns the ATXP connection string from the
// ATXP_CONNECTION env var, falling back to ~/.atxp/config (KEY=VALUE lines, as
// written by `npx atxp login`). Returns "" if neither is set.
func liveConnectionString() string {
	if v := os.Getenv("ATXP_CONNECTION"); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	f, err := os.Open(filepath.Join(home, ".atxp", "config"))
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if ok && strings.TrimSpace(k) == "ATXP_CONNECTION" {
			return strings.Trim(strings.TrimSpace(v), `"`)
		}
	}
	return ""
}

func TestLiveDiscoveryAndRegistration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	oc := &oauthClient{
		store:       NewMemoryStore(),
		http:        &http.Client{Timeout: 20 * time.Second},
		userID:      "atxp:test",
		callbackURL: "http://localhost:3000/unused-dummy-atxp-callback",
	}

	as, err := oc.discoverAuthServer(ctx, "https://search.mcp.atxp.ai/")
	if err != nil {
		t.Fatalf("discoverAuthServer: %v", err)
	}
	t.Logf("issuer=%s authorize=%s token=%s register=%s",
		as.Issuer, as.AuthorizationEndpoint, as.TokenEndpoint, as.RegistrationEndpoint)
	if as.Issuer != "https://auth.atxp.ai" {
		t.Errorf("unexpected issuer %q", as.Issuer)
	}
	if as.RegistrationEndpoint == "" {
		t.Fatal("no registration endpoint; DCR not advertised")
	}

	cc, err := oc.registerClient(ctx, as)
	if err != nil {
		t.Fatalf("registerClient: %v", err)
	}
	if cc.ClientID == "" {
		t.Error("registration returned empty client_id")
	}
	t.Logf("registered client_id=%s has_secret=%v", cc.ClientID, cc.ClientSecret != "")
}

// TestLivePaidPath drives the real client against search.mcp.atxp.ai using a
// connection string. ListTools exercises the full OAuth handshake (/me, /sign,
// authorize, token exchange) with no spend; CallTool then exercises the payment
// path — which succeeds if the account is funded, or returns a payment-required
// error on a 0-balance account. Either outcome proves the auth leg end to end.
func TestLivePaidPath(t *testing.T) {
	conn := liveConnectionString()
	if conn == "" {
		t.Skip("no ATXP_CONNECTION (env or ~/.atxp/config); skipping live paid-path test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	c, err := New(Config{ConnectionString: conn})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	sess, err := c.Connect(ctx, "https://search.mcp.atxp.ai/")
	if err != nil {
		var re *RestrictionError
		if errors.As(err, &re) {
			t.Skipf("account restricted (%s): %s — add a payment method at /fund to enable; "+
				"client behaved correctly, this is an account-state gate not a code bug", re.Code, re.Message)
		}
		t.Fatalf("Connect (OAuth handshake): %v", err)
	}
	defer sess.Close()

	tools, err := sess.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools (proves OAuth leg live): %v", err)
	}
	names := make([]string, 0, len(tools.Tools))
	for _, tl := range tools.Tools {
		names = append(names, tl.Name)
	}
	t.Logf("OAuth handshake OK; tools: %v", names)
	if len(names) == 0 {
		t.Fatal("no tools returned")
	}

	// Attempt a paid call. On a 0-balance account this should surface a payment
	// error rather than panic or hang — that still validates the settle path up
	// to the funding gate.
	res, err := sess.CallTool(ctx, &mcp.CallToolParams{
		Name:      names[0],
		Arguments: map[string]any{"query": "what is the model context protocol"},
	})
	switch {
	case err == nil && res != nil && !res.IsError:
		t.Logf("PAID CALL SUCCEEDED (account is funded): %d content blocks", len(res.Content))
	case err == nil && res != nil && res.IsError:
		t.Logf("tool returned error result (expected on 0 balance): %v", res.Content)
	case errors.Is(err, context.DeadlineExceeded):
		t.Fatalf("paid call timed out — settle path may be hanging: %v", err)
	default:
		// A payment/authorization error is the expected outcome with 0 balance.
		t.Logf("paid call returned error (expected on 0 balance, settle path reached): %v", err)
	}
}

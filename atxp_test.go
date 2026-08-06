package atxp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseConnectionString(t *testing.T) {
	a, err := NewATXPAccount("https://accounts.atxp.ai/?connection_token=tok123&account_id=abc", nil)
	if err != nil {
		t.Fatal(err)
	}
	if a.Origin() != "https://accounts.atxp.ai" {
		t.Errorf("origin = %q", a.Origin())
	}
	if got := a.basicAuth(); got != "Basic "+base64.StdEncoding.EncodeToString([]byte("tok123:")) {
		t.Errorf("basicAuth = %q", got)
	}
	id, err := a.AccountID(context.Background())
	if err != nil || id != "atxp:abc" {
		t.Errorf("AccountID = %q, %v (no HTTP call expected when account_id present)", id, err)
	}
}

func TestConnectionStringErrors(t *testing.T) {
	if _, err := NewATXPAccount("", nil); err == nil {
		t.Error("empty string should error")
	}
	if _, err := NewATXPAccount("https://x/?account_id=a", nil); err == nil {
		t.Error("missing connection_token should error")
	}
}

func TestAccountEndpoints(t *testing.T) {
	var sawSign, sawAuthorize, sawMe bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/me":
			if r.Header.Get("Authorization") != "Bearer tok" {
				t.Errorf("/me auth = %q, want Bearer", r.Header.Get("Authorization"))
			}
			sawMe = true
			json.NewEncoder(w).Encode(map[string]string{"accountId": "id42"})
		case "/sign":
			if !strings.HasPrefix(r.Header.Get("Authorization"), "Basic ") {
				t.Errorf("/sign auth = %q, want Basic", r.Header.Get("Authorization"))
			}
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			if body["codeChallenge"] != "chal" {
				t.Errorf("/sign codeChallenge = %v", body["codeChallenge"])
			}
			sawSign = true
			json.NewEncoder(w).Encode(map[string]string{"jwt": "signed.jwt"})
		case "/authorize/auto":
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			if body["currency"] != "USDC" {
				t.Errorf("/authorize currency = %v", body["currency"])
			}
			sawAuthorize = true
			cred, _ := json.Marshal(map[string]string{"foo": "bar"})
			json.NewEncoder(w).Encode(map[string]string{"protocol": "atxp", "credential": string(cred)})
		default:
			http.Error(w, "nope", 404)
		}
	}))
	defer srv.Close()

	a, err := NewATXPAccount(srv.URL+"/?connection_token=tok", nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	id, err := a.AccountID(ctx)
	if err != nil || id != "atxp:id42" {
		t.Fatalf("AccountID = %q, %v", id, err)
	}
	jwt, err := a.SignChallenge(ctx, "chal")
	if err != nil || jwt != "signed.jwt" {
		t.Fatalf("SignChallenge = %q, %v", jwt, err)
	}
	res, err := a.Authorize(ctx, AuthorizeParams{Protocols: []string{"atxp"}, Amount: "0.01"})
	if err != nil {
		t.Fatal(err)
	}
	// atxp credential must have the connection token injected.
	var cred map[string]string
	if err := json.Unmarshal([]byte(res.Credential), &cred); err != nil {
		t.Fatal(err)
	}
	if cred["sourceAccountToken"] != "tok" {
		t.Errorf("credential missing injected sourceAccountToken: %v", cred)
	}
	if !sawMe || !sawSign || !sawAuthorize {
		t.Errorf("missed an endpoint: me=%v sign=%v authorize=%v", sawMe, sawSign, sawAuthorize)
	}
}

func TestMemoryStoreParentPathWalk(t *testing.T) {
	s := NewMemoryStore()
	s.SaveAccessToken("u", "https://x.ai/mcp", AccessToken{AccessToken: "T"})
	// Exact and child paths resolve; unrelated origin does not.
	if tok, ok := s.GetAccessToken("u", "https://x.ai/mcp/tool/search"); !ok || tok.AccessToken != "T" {
		t.Errorf("child path should resolve to parent token: %v %v", tok, ok)
	}
	if _, ok := s.GetAccessToken("u", "https://other.ai/mcp"); ok {
		t.Error("unrelated origin should not resolve")
	}
}

// Regression: a token saved for the bare origin (no path — what authenticate()
// does when the resource URL has no path component, e.g. after
// normalizeResourceURL strips a trailing well-known suffix) must still resolve
// for a request to a single-segment path on that origin, e.g. "/mcp". The
// parent-path walk used to return the origin WITH a trailing slash at that
// step, which never matched the no-trailing-slash key trimToPath saves under,
// and the following iteration then saw path "/" and gave up one level early —
// so a resource server whose endpoint lives at a path other than "/" (i.e.
// almost any real one) could authenticate every single request and never
// reuse the token.
func TestMemoryStoreParentPathWalkToBareOrigin(t *testing.T) {
	s := NewMemoryStore()
	s.SaveAccessToken("u", "https://x.ai", AccessToken{AccessToken: "T"})
	if tok, ok := s.GetAccessToken("u", "https://x.ai/mcp"); !ok || tok.AccessToken != "T" {
		t.Errorf("single-segment path should resolve to a token saved at the bare origin: %v %v", tok, ok)
	}
}

func TestResourceFromWWWAuthenticate(t *testing.T) {
	h := `Bearer resource_metadata="https://search.mcp.atxp.ai/.well-known/oauth-protected-resource/"`
	got := resourceFromWWWAuthenticate(h)
	want := "https://search.mcp.atxp.ai/"
	if got != want {
		t.Errorf("got %q want %q", got, want)
	}
	if resourceFromWWWAuthenticate("https://bare.example/mcp") != "https://bare.example/mcp" {
		t.Error("bare-URL form should be accepted")
	}
}

func TestParseMCPPaymentSSE(t *testing.T) {
	errObj := map[string]any{
		"jsonrpc": "2.0", "id": 1,
		"error": map[string]any{
			"code":    codePaymentRequiredOmni,
			"message": "payment required",
			"data":    map[string]any{"chargeAmount": "0.01", "paymentRequestId": "pr1", "paymentRequestUrl": "https://accounts/pr/1"},
		},
	}
	b, _ := json.Marshal(errObj)
	sse := "event: message\ndata: " + string(b) + "\n\n"
	pc := parseMCPPayment("text/event-stream", []byte(sse))
	if pc == nil {
		t.Fatal("expected a challenge from SSE body")
	}
	if pc.chargeAmount != "0.01" || pc.paymentRequestID != "pr1" {
		t.Errorf("parsed challenge = %+v", pc)
	}
}

func TestBuildAuthorizeParamsX402(t *testing.T) {
	rt := &roundTripper{}
	x402 := map[string]any{
		"x402Version": 2,
		"accepts": []map[string]any{
			{"network": "atxp", "payTo": "skip"},
			{"network": "base", "payTo": "0xdead", "amount": "0.05"},
		},
	}
	xb, _ := json.Marshal(x402)
	pc := &paymentChallenge{x402: xb}
	p, err := rt.buildAuthorizeParams(context.Background(), pc)
	if err != nil {
		t.Fatal(err)
	}
	if p.Destination != "0xdead" || p.Amount != "0.05" {
		t.Errorf("x402 dest/amount = %q/%q", p.Destination, p.Amount)
	}
	if !contains(p.Protocols, "x402") {
		t.Errorf("protocols should include x402: %v", p.Protocols)
	}
}

func TestApplyPaymentHeader(t *testing.T) {
	cases := map[string]struct{ wantKey, wantVal string }{
		"x402": {"X-Payment", "cred"},
		"mpp":  {"Authorization", "Payment cred"},
		"atxp": {"X-Atxp-Payment", "cred"},
	}
	for proto, want := range cases {
		h := http.Header{}
		applyPaymentHeader(h, AuthorizeResult{Protocol: proto, Credential: "cred"})
		if got := h.Get(want.wantKey); got != want.wantVal {
			t.Errorf("%s: %s = %q, want %q", proto, want.wantKey, got, want.wantVal)
		}
	}
}

// TestFullFlow_OAuthThenPayment drives the whole transport against mock AS, MCP,
// and accounts servers: 401 → OAuth handshake → MCP payment error → settle → 200.
func TestFullFlow_OAuthThenPayment(t *testing.T) {
	// Auth server: discovery, DCR, authorize (redirect=false), token.
	var as *httptest.Server
	as = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			json.NewEncoder(w).Encode(authServer{
				Issuer:                as.URL,
				AuthorizationEndpoint: as.URL + "/authorize",
				TokenEndpoint:         as.URL + "/token",
				RegistrationEndpoint:  as.URL + "/register",
			})
		case "/register":
			json.NewEncoder(w).Encode(map[string]string{"client_id": "cid", "client_secret": "csec"})
		case "/authorize":
			if r.Header.Get("Authorization") != "Bearer signed.jwt" {
				t.Errorf("authorize missing signed JWT: %q", r.Header.Get("Authorization"))
			}
			// redirect=false hack: 200 with {redirect: callback?code&state}
			state := r.URL.Query().Get("state")
			json.NewEncoder(w).Encode(map[string]string{
				"redirect": "http://cb/done?code=AUTHCODE&state=" + state,
			})
		case "/token":
			r.ParseForm()
			if r.Form.Get("code") != "AUTHCODE" || r.Form.Get("code_verifier") == "" {
				t.Errorf("token req bad: %v", r.Form)
			}
			json.NewEncoder(w).Encode(map[string]any{"access_token": "ACCESS", "refresh_token": "R", "expires_in": 3600})
		default:
			http.Error(w, "no", 404)
		}
	}))
	defer as.Close()

	// Accounts server: /me, /sign, /authorize/auto, /spend-permission.
	accounts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/spend-permission":
			json.NewEncoder(w).Encode(map[string]string{"spendPermissionToken": "spt"})
		case "/sign":
			json.NewEncoder(w).Encode(map[string]string{"jwt": "signed.jwt"})
		case "/authorize/auto":
			cred, _ := json.Marshal(map[string]string{"c": "1"})
			json.NewEncoder(w).Encode(map[string]string{"protocol": "atxp", "credential": string(cred)})
		default:
			http.Error(w, "no", 404)
		}
	}))
	defer accounts.Close()

	// MCP tool server: 401 until OAuth'd, then payment-error until paid, then 200.
	var mcp *httptest.Server
	authed, paid := false, false
	mcp = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/oauth-protected-resource" {
			json.NewEncoder(w).Encode(map[string]any{"authorization_servers": []string{as.URL}})
			return
		}
		if !authed {
			if r.Header.Get("Authorization") == "Bearer ACCESS" {
				authed = true
			} else {
				w.Header().Set("WWW-Authenticate",
					`Bearer resource_metadata="`+mcp.URL+`/.well-known/oauth-protected-resource"`)
				w.WriteHeader(401)
				return
			}
		}
		if !paid {
			if h := r.Header.Get("X-Atxp-Payment"); h != "" {
				paid = true
			} else {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]any{
					"jsonrpc": "2.0", "id": 1,
					"error": map[string]any{"code": codePaymentRequiredOmni, "message": "pay",
						"data": map[string]any{"chargeAmount": "0.01", "paymentRequestId": "pr1"}},
				})
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"ok":true}}`)
	}))
	defer mcp.Close()

	c, err := New(Config{ConnectionString: accounts.URL + "/?connection_token=tok&account_id=acc"})
	if err != nil {
		t.Fatal(err)
	}
	hc := c.HTTPClient()
	resp, err := hc.Post(mcp.URL+"/", "application/json", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || !strings.Contains(string(body), `"ok":true`) {
		t.Fatalf("final response = %d %s", resp.StatusCode, body)
	}
	if !authed || !paid {
		t.Errorf("flow incomplete: authed=%v paid=%v", authed, paid)
	}
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

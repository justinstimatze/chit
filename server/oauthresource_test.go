package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	atxp "github.com/justinstimatze/chit"
)

// fakeAS is an httptest authorization server serving discovery, dynamic client
// registration, and RFC 7662 introspection.
type fakeAS struct {
	srv           *httptest.Server
	registrations int32
	introspectFn  func(token string) (int, string)
}

func newFakeAS(t *testing.T) *fakeAS {
	t.Helper()
	f := &fakeAS{}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		base := "http://" + r.Host
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 base,
			"registration_endpoint":  base + "/register",
			"introspection_endpoint": base + "/introspect",
		})
	})
	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-ATXP-Registration-Type") != "server" {
			t.Errorf("registration type header = %q, want server", r.Header.Get("X-ATXP-Registration-Type"))
		}
		n := atomic.AddInt32(&f.registrations, 1)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"client_id":     "client-" + string(rune('0'+n)),
			"client_secret": "secret-xyz",
		})
	})
	mux.HandleFunc("/introspect", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			t.Error("introspection request missing Basic auth")
		}
		_ = r.ParseForm()
		token := r.Form.Get("token")
		status, body := 200, `{"active":true,"sub":"atxp:user","scope":"read"}`
		if f.introspectFn != nil {
			status, body = f.introspectFn(token)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func newTestResourceClient(t *testing.T, f *fakeAS) *resourceClient {
	t.Helper()
	return newResourceClient(atxp.NewMemoryStore(), f.srv.Client(), "merchant-conn-token", "test", true, nopLogger{})
}

func TestResourceClientCredentialsCached(t *testing.T) {
	f := newFakeAS(t)
	rc := newTestResourceClient(t, f)
	id1, sec1, err := rc.clientCredentials(context.Background(), f.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if id1 == "" || sec1 == "" {
		t.Fatal("empty credentials")
	}
	// Second call must reuse the stored credentials (no second registration).
	id2, _, err := rc.clientCredentials(context.Background(), f.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if id2 != id1 {
		t.Errorf("credentials changed: %q -> %q", id1, id2)
	}
	if got := atomic.LoadInt32(&f.registrations); got != 1 {
		t.Errorf("registrations = %d, want 1 (cached)", got)
	}
}

func TestResourceClientIntrospectActive(t *testing.T) {
	f := newFakeAS(t)
	rc := newTestResourceClient(t, f)
	td, err := rc.introspectToken(context.Background(), f.srv.URL, "tok")
	if err != nil {
		t.Fatal(err)
	}
	if !td.Active || td.Sub != "atxp:user" {
		t.Errorf("token data = %+v", td)
	}
}

func TestResourceClientIntrospectReRegistersOn401(t *testing.T) {
	f := newFakeAS(t)
	var called int32
	f.introspectFn = func(token string) (int, string) {
		// First call 401 (stale creds), second call succeeds.
		if atomic.AddInt32(&called, 1) == 1 {
			return 401, `{"error":"invalid_client"}`
		}
		return 200, `{"active":true,"sub":"atxp:user"}`
	}
	rc := newTestResourceClient(t, f)
	td, err := rc.introspectToken(context.Background(), f.srv.URL, "tok")
	if err != nil {
		t.Fatalf("introspect after re-register: %v", err)
	}
	if !td.Active {
		t.Error("expected active token after re-register")
	}
	if atomic.LoadInt32(&f.registrations) != 2 {
		t.Errorf("registrations = %d, want 2 (initial + re-register)", f.registrations)
	}
}

func TestResourceClientRejectsPlaintextWhenSecure(t *testing.T) {
	// Without AllowHTTP, a non-HTTPS auth server must be refused so the
	// connection token never crosses the wire in the clear.
	rc := newResourceClient(atxp.NewMemoryStore(), http.DefaultClient, "tok", "test", false, nopLogger{})
	_, _, err := rc.clientCredentials(context.Background(), "http://insecure.example")
	if err == nil || !strings.Contains(err.Error(), "non-HTTPS") {
		t.Fatalf("expected non-HTTPS refusal, got %v", err)
	}
}

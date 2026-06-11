package server

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"
)

type fakeIntrospector struct {
	data TokenData
	err  error
}

func (f fakeIntrospector) introspectToken(context.Context, string, string) (TokenData, error) {
	return f.data, f.err
}

func resURL() *url.URL {
	u, _ := url.Parse("https://merchant.example/mcp")
	return u
}

func TestCheckTokenNoHeader(t *testing.T) {
	tc := checkTokenCore(context.Background(), fakeIntrospector{}, "https://auth", resURL(), "", "", fixedTime)
	if tc.Passes || tc.Problem != ProblemNoToken {
		t.Errorf("got passes=%v problem=%v", tc.Passes, tc.Problem)
	}
	if tc.ResourceMetadataURL != "https://merchant.example/.well-known/oauth-protected-resource/mcp" {
		t.Errorf("prm url = %q", tc.ResourceMetadataURL)
	}
}

func TestCheckTokenNonBearer(t *testing.T) {
	tc := checkTokenCore(context.Background(), fakeIntrospector{}, "https://auth", resURL(), "Basic abc", "", fixedTime)
	if tc.Passes || tc.Problem != ProblemNonBearer {
		t.Errorf("got passes=%v problem=%v", tc.Passes, tc.Problem)
	}
}

func TestCheckTokenActive(t *testing.T) {
	in := fakeIntrospector{data: TokenData{Active: true, Sub: "atxp:user"}}
	tc := checkTokenCore(context.Background(), in, "https://auth", resURL(), "Bearer tok", "", fixedTime)
	if !tc.Passes {
		t.Fatalf("expected pass, got problem %v", tc.Problem)
	}
	if tc.Data == nil || tc.Data.Sub != "atxp:user" {
		t.Errorf("data = %+v", tc.Data)
	}
}

func TestCheckTokenInactive(t *testing.T) {
	in := fakeIntrospector{data: TokenData{Active: false}}
	tc := checkTokenCore(context.Background(), in, "https://auth", resURL(), "Bearer tok", "", fixedTime)
	if tc.Passes || tc.Problem != ProblemInvalidToken {
		t.Errorf("got passes=%v problem=%v", tc.Passes, tc.Problem)
	}
}

func TestCheckTokenIntrospectErrorFailsClosed(t *testing.T) {
	in := fakeIntrospector{err: errors.New("network down")}
	tc := checkTokenCore(context.Background(), in, "https://auth", resURL(), "Bearer tok", "", fixedTime)
	if tc.Passes || tc.Problem != ProblemIntrospectErr {
		t.Errorf("got passes=%v problem=%v", tc.Passes, tc.Problem)
	}
}

func TestCheckTokenExpiredRejected(t *testing.T) {
	// Hardening: active=true but exp already past → reject.
	past := fixedTime.Add(-time.Hour).Unix()
	in := fakeIntrospector{data: TokenData{Active: true, Sub: "u", Exp: past}}
	tc := checkTokenCore(context.Background(), in, "https://auth", resURL(), "Bearer tok", "", fixedTime)
	if tc.Passes || tc.Problem != ProblemInvalidToken {
		t.Errorf("expired token: passes=%v problem=%v", tc.Passes, tc.Problem)
	}
}

func TestCheckTokenAudienceEnforced(t *testing.T) {
	in := fakeIntrospector{data: TokenData{Active: true, Sub: "u", Aud: stringOrSlice{"https://other.example"}}}
	// Wrong audience → reject.
	tc := checkTokenCore(context.Background(), in, "https://auth", resURL(), "Bearer tok", "https://merchant.example/mcp", fixedTime)
	if tc.Passes || tc.Problem != ProblemInvalidAud {
		t.Errorf("wrong aud: passes=%v problem=%v", tc.Passes, tc.Problem)
	}
	// Correct audience present → pass.
	in2 := fakeIntrospector{data: TokenData{Active: true, Sub: "u", Aud: stringOrSlice{"https://merchant.example/mcp", "x"}}}
	tc2 := checkTokenCore(context.Background(), in2, "https://auth", resURL(), "Bearer tok", "https://merchant.example/mcp", fixedTime)
	if !tc2.Passes {
		t.Errorf("correct aud should pass, got problem %v", tc2.Problem)
	}
}

func TestChallengeResponseMapping(t *testing.T) {
	cases := []struct {
		problem TokenProblem
		status  int
	}{
		{ProblemNoToken, 401},
		{ProblemNonBearer, 400},
		{ProblemInvalidToken, 401},
		{ProblemInvalidAud, 401},
		{ProblemNSF, 403},
		{ProblemIntrospectErr, 502},
	}
	for _, c := range cases {
		resp := ChallengeResponse(TokenCheck{Passes: false, Problem: c.problem, ResourceMetadataURL: "https://m/.well-known/oauth-protected-resource"})
		if resp.Status != c.status {
			t.Errorf("problem %v: status %d, want %d", c.problem, resp.Status, c.status)
		}
		if resp.Headers["WWW-Authenticate"] == "" {
			t.Errorf("problem %v: missing WWW-Authenticate", c.problem)
		}
	}
	if ChallengeResponse(TokenCheck{Passes: true}) != nil {
		t.Error("passing check should yield no challenge response")
	}
}

func TestStringOrSliceUnmarshal(t *testing.T) {
	var s stringOrSlice
	if err := s.UnmarshalJSON([]byte(`"single"`)); err != nil || len(s) != 1 || s[0] != "single" {
		t.Errorf("single: %v %+v", err, s)
	}
	var s2 stringOrSlice
	if err := s2.UnmarshalJSON([]byte(`["a","b"]`)); err != nil || len(s2) != 2 {
		t.Errorf("array: %v %+v", err, s2)
	}
}

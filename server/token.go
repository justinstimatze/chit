package server

import (
	"context"
	"net/url"
	"strings"
	"time"
)

// Resource-server token checking. Ported from core/token.ts + core/oauth.ts and
// protectedResourceMetadata.ts, with two deliberate security hardenings over the
// TS reference (which only checks `active`):
//
//   - Expiry: if the introspection result carries an `exp`, a token already past
//     it is rejected even should the AS erroneously report active=true.
//   - Audience: if the merchant configures an expected audience, the token's
//     `aud` must contain it. The TS SDK defines the INVALID_AUDIENCE problem but
//     never actually checks; a resource server that skips the audience check can
//     be made to accept a token minted for a different resource.

// TokenProblem categorizes why a token check failed. Ported from
// @atxp/server TokenProblem.
type TokenProblem string

const (
	ProblemNoToken       TokenProblem = "NO-TOKEN"
	ProblemNonBearer     TokenProblem = "NON-BEARER-AUTH-HEADER"
	ProblemInvalidToken  TokenProblem = "INVALID-TOKEN"
	ProblemInvalidAud    TokenProblem = "INVALID-AUDIENCE"
	ProblemNSF           TokenProblem = "NON-SUFFICIENT-FUNDS"
	ProblemIntrospectErr TokenProblem = "INTROSPECT-ERROR"
)

// TokenCheck is the result of CheckToken. Passes reports whether the caller is
// authenticated; on failure Problem says why and ResourceMetadataURL is the
// value for the WWW-Authenticate challenge.
type TokenCheck struct {
	Passes              bool
	Problem             TokenProblem
	Token               string
	Data                *TokenData
	ResourceMetadataURL string
}

// introspector validates a bearer token against an authorization server.
type introspector interface {
	introspectToken(ctx context.Context, authServer, token string) (TokenData, error)
}

// checkTokenCore is the platform-agnostic token check. Ported from
// core/token.ts checkTokenCore, plus the expiry/audience hardenings.
func checkTokenCore(ctx context.Context, in introspector, authServer string, resourceURL *url.URL, authHeader string, expectedAudience string, now time.Time) TokenCheck {
	prmURL := resourceURL.Scheme + "://" + resourceURL.Host +
		"/.well-known/oauth-protected-resource" + resourceURL.Path

	fail := func(p TokenProblem, token string) TokenCheck {
		return TokenCheck{Passes: false, Problem: p, Token: token, ResourceMetadataURL: prmURL}
	}

	if authHeader == "" {
		return fail(ProblemNoToken, "")
	}
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return fail(ProblemNonBearer, "")
	}
	token := strings.TrimPrefix(authHeader, "Bearer ")

	td, err := in.introspectToken(ctx, authServer, token)
	if err != nil {
		return fail(ProblemIntrospectErr, token)
	}
	if !td.Active {
		return fail(ProblemInvalidToken, token)
	}
	// Hardening: reject an expired token even if active was (wrongly) true.
	if td.Exp > 0 && !now.Before(time.Unix(td.Exp, 0)) {
		return fail(ProblemInvalidToken, token)
	}
	// Hardening: enforce audience binding when configured.
	if expectedAudience != "" && !td.Aud.contains(expectedAudience) {
		return fail(ProblemInvalidAud, token)
	}

	data := td
	return TokenCheck{Passes: true, Token: token, Data: &data, ResourceMetadataURL: prmURL}
}

// OAuthChallengeResponse is the HTTP response a resource server returns when a
// token check fails. Ported from core/oauth.ts createOAuthChallengeResponseCore.
type OAuthChallengeResponse struct {
	Status  int
	Headers map[string]string
	Body    string
}

// ChallengeResponse maps a failed TokenCheck to the RFC 6750 HTTP challenge a
// resource server should return. Returns nil when the check passed.
func ChallengeResponse(tc TokenCheck) *OAuthChallengeResponse {
	if tc.Passes {
		return nil
	}
	status := 401
	body := "{}"
	switch tc.Problem {
	case ProblemNoToken:
		// 401 with empty body.
	case ProblemNonBearer:
		status = 400
		body = `{"error":"invalid_request","error_description":"Authorization header did not include a Bearer token"}`
	case ProblemInvalidToken:
		body = `{"error":"invalid_token","error_description":"Token is not active"}`
	case ProblemInvalidAud:
		body = `{"error":"invalid_token","error_description":"Token does not match the expected audience"}`
	case ProblemNSF:
		status = 403
		body = `{"error":"insufficient_scope","error_description":"Non sufficient funds"}`
	case ProblemIntrospectErr:
		status = 502
		body = `{"error":"server_error","error_description":"An internal server error occurred"}`
	}
	return &OAuthChallengeResponse{
		Status: status,
		Headers: map[string]string{
			"Content-Type":     "application/json",
			"WWW-Authenticate": `Bearer resource_metadata="` + tc.ResourceMetadataURL + `"`,
		},
		Body: body,
	}
}

// ProtectedResourceMetadata is the RFC 9728 document a resource server serves at
// /.well-known/oauth-protected-resource. Ported from protectedResourceMetadata.ts.
type ProtectedResourceMetadata struct {
	Resource               string   `json:"resource"`
	ResourceName           string   `json:"resource_name"`
	AuthorizationServers   []string `json:"authorization_servers"`
	BearerMethodsSupported []string `json:"bearer_methods_supported"`
	ScopesSupported        []string `json:"scopes_supported"`
}

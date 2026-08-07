package atxp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// authServer is the subset of OAuth authorization-server metadata we use
// (RFC 8414). Discovered from the resource server's protected-resource metadata.
type authServer struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	RegistrationEndpoint  string `json:"registration_endpoint"`
}

// oauthClient runs the MCP OAuth 2.1 flow (RFC 9728 discovery + RFC 7591 dynamic
// client registration + PKCE), with the two ATXP-specific deviations: the
// authorization request is a server-to-server GET carrying an account-signed JWT
// (no browser), and the authorization code comes back via Location or a
// {"redirect": "..."} body rather than a real user redirect.
type oauthClient struct {
	account     Account
	store       Store
	http        *http.Client
	userID      string // qualified account id; the token-store namespace
	callbackURL string
}

// resourceFromWWWAuthenticate parses a 401's WWW-Authenticate header into the
// resource (protected-resource metadata) URL. Returns "" if not present.
//
// Canonical form (observed live):
//
//	WWW-Authenticate: Bearer resource_metadata="https://search.mcp.atxp.ai/.well-known/oauth-protected-resource/"
//
// Some older servers send a bare URL; we accept that too.
func resourceFromWWWAuthenticate(header string) string {
	if header == "" {
		return ""
	}
	if i := strings.Index(header, `resource_metadata="`); i >= 0 {
		rest := header[i+len(`resource_metadata="`):]
		if j := strings.Index(rest, `"`); j >= 0 {
			return normalizeResourceURL(rest[:j])
		}
	}
	if strings.HasPrefix(header, "http://") || strings.HasPrefix(header, "https://") {
		return normalizeResourceURL(strings.TrimSpace(header))
	}
	return ""
}

// normalizeResourceURL standardizes on the resource URL itself by stripping the
// well-known PRM suffix (mirrors oAuthResource.ts normalizeResourceServerUrl).
func normalizeResourceURL(u string) string {
	return strings.Replace(u, "/.well-known/oauth-protected-resource", "", 1)
}

// discoverAuthServer resolves the authorization server for a resource server,
// following RFC 9728 with the OAuth-AS fallback some ATXP servers use.
func (c *oauthClient) discoverAuthServer(ctx context.Context, resourceURL string) (authServer, error) {
	resourceURL = normalizeResourceURL(resourceURL)
	base := strings.TrimRight(resourceURL, "/")

	// 1. Protected Resource Metadata.
	var issuer string
	prm := base + "/.well-known/oauth-protected-resource"
	status, body, err := c.get(ctx, prm)
	if err != nil {
		return authServer{}, fmt.Errorf("fetch PRM %s: %w", prm, err)
	}
	if status == http.StatusOK {
		var doc struct {
			AuthorizationServers []string `json:"authorization_servers"`
		}
		if err := json.Unmarshal(body, &doc); err == nil && len(doc.AuthorizationServers) > 0 {
			issuer = doc.AuthorizationServers[0]
		}
	}
	// 2. Fallback: OAuth AS metadata served from the resource server root.
	if issuer == "" {
		u, _ := url.Parse(resourceURL)
		asURL := u.Scheme + "://" + u.Host + "/.well-known/oauth-authorization-server"
		st2, b2, err := c.get(ctx, asURL)
		if err != nil {
			return authServer{}, fmt.Errorf("fetch AS fallback %s: %w", asURL, err)
		}
		if st2 == http.StatusOK {
			var doc struct {
				Issuer string `json:"issuer"`
			}
			if err := json.Unmarshal(b2, &doc); err == nil {
				issuer = doc.Issuer
			}
		}
	}
	if issuer == "" {
		return authServer{}, fmt.Errorf("no authorization server found for %s", resourceURL)
	}

	// 3. Authorization-server metadata discovery.
	return c.authServerFromIssuer(ctx, issuer)
}

func (c *oauthClient) authServerFromIssuer(ctx context.Context, issuer string) (authServer, error) {
	base := strings.TrimRight(issuer, "/")
	disco := base + "/.well-known/oauth-authorization-server"
	status, body, err := c.get(ctx, disco)
	if err != nil {
		return authServer{}, fmt.Errorf("discovery %s: %w", disco, err)
	}
	if status != http.StatusOK {
		return authServer{}, fmt.Errorf("discovery %s: status %d", disco, status)
	}
	var as authServer
	if err := json.Unmarshal(body, &as); err != nil {
		return authServer{}, fmt.Errorf("decode AS metadata: %w", err)
	}
	if as.Issuer == "" {
		as.Issuer = issuer
	}
	if as.AuthorizationEndpoint == "" || as.TokenEndpoint == "" {
		return authServer{}, fmt.Errorf("AS metadata missing endpoints for %s", issuer)
	}
	return as, nil
}

// clientCredentials returns cached credentials for the issuer, registering a new
// client (RFC 7591) if none exist.
func (c *oauthClient) clientCredentials(ctx context.Context, as authServer) (ClientCredentials, error) {
	if cc, ok := c.store.GetClientCredentials(as.Issuer); ok {
		return cc, nil
	}
	cc, err := c.registerClient(ctx, as)
	if err != nil {
		return ClientCredentials{}, err
	}
	c.store.SaveClientCredentials(as.Issuer, cc)
	return cc, nil
}

func (c *oauthClient) registerClient(ctx context.Context, as authServer) (ClientCredentials, error) {
	if as.RegistrationEndpoint == "" {
		return ClientCredentials{}, fmt.Errorf("AS %s does not support dynamic client registration", as.Issuer)
	}
	meta := map[string]any{
		"redirect_uris":              []string{c.callbackURL},
		"response_types":             []string{"code"},
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"token_endpoint_auth_method": "client_secret_post",
		"client_name":                "chit ATXP client",
	}
	buf, _ := json.Marshal(meta)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, as.RegistrationEndpoint, strings.NewReader(string(buf)))
	if err != nil {
		return ClientCredentials{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-ATXP-Registration-Type", "client")
	resp, err := c.http.Do(req)
	if err != nil {
		return ClientCredentials{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ClientCredentials{}, fmt.Errorf("client registration failed: status %d: %s", resp.StatusCode, body)
	}
	var reg struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	if err := json.Unmarshal(body, &reg); err != nil {
		return ClientCredentials{}, fmt.Errorf("decode registration: %w", err)
	}
	if reg.ClientID == "" {
		return ClientCredentials{}, fmt.Errorf("registration returned no client_id")
	}
	return ClientCredentials{
		ClientID:     reg.ClientID,
		ClientSecret: reg.ClientSecret,
		RedirectURI:  c.callbackURL,
	}, nil
}

// generatePKCE creates and stores PKCE values for a flow, returning the state.
func (c *oauthClient) generatePKCE(flowURL, resourceURL string) (PKCEValues, string, error) {
	verifier, err := randomURLSafe(32)
	if err != nil {
		return PKCEValues{}, "", err
	}
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	state, err := randomURLSafe(32)
	if err != nil {
		return PKCEValues{}, "", err
	}
	v := PKCEValues{
		URL:           flowURL,
		CodeVerifier:  verifier,
		CodeChallenge: challenge,
		ResourceURL:   resourceURL,
	}
	c.store.SavePKCE(c.userID, state, v)
	return v, state, nil
}

// buildAuthorizationURL assembles the OAuth authorization request URL.
func buildAuthorizationURL(as authServer, cc ClientCredentials, pkce PKCEValues, state, resourceURL, spendPermissionToken string) (string, error) {
	u, err := url.Parse(as.AuthorizationEndpoint)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("client_id", cc.ClientID)
	q.Set("redirect_uri", cc.RedirectURI)
	q.Set("response_type", "code")
	q.Set("code_challenge", pkce.CodeChallenge)
	q.Set("code_challenge_method", "S256")
	q.Set("state", state)
	q.Set("resource", resourceURL)
	if spendPermissionToken != "" {
		q.Set("spend_permission_token", spendPermissionToken)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// exchangeCode swaps an authorization code for tokens at the token endpoint.
func (c *oauthClient) exchangeCode(ctx context.Context, as authServer, cc ClientCredentials, code, codeVerifier string) (AccessToken, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", cc.RedirectURI)
	form.Set("code_verifier", codeVerifier)
	form.Set("client_id", cc.ClientID)
	if cc.ClientSecret != "" {
		form.Set("client_secret", cc.ClientSecret)
	}
	return c.tokenRequest(ctx, as, form)
}

func (c *oauthClient) tokenRequest(ctx context.Context, as authServer, form url.Values) (AccessToken, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, as.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return AccessToken{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return AccessToken{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return AccessToken{}, fmt.Errorf("token endpoint status %d: %s", resp.StatusCode, body)
	}
	var tok struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return AccessToken{}, fmt.Errorf("decode token response: %w", err)
	}
	if tok.AccessToken == "" {
		return AccessToken{}, fmt.Errorf("token response missing access_token")
	}
	return AccessToken{
		AccessToken:  tok.AccessToken,
		RefreshToken: tok.RefreshToken,
	}, nil
}

// get performs a GET and returns (status, body). Non-2xx is not an error here;
// discovery logic branches on the status code.
func (c *oauthClient) get(ctx context.Context, u string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

// authenticate runs the full OAuth handshake for a resource server and stores
// the resulting access token under (userID, resourceURL).
func (c *oauthClient) authenticate(ctx context.Context, resourceURL string) error {
	resourceURL = normalizeResourceURL(resourceURL)
	as, err := c.discoverAuthServer(ctx, resourceURL)
	if err != nil {
		return err
	}
	cc, err := c.clientCredentials(ctx, as)
	if err != nil {
		return err
	}
	// Best-effort spend permission (no-op for accounts that don't support it).
	spendToken, _ := c.account.SpendPermission(ctx, resourceURL)

	pkce, state, err := c.generatePKCE(resourceURL, resourceURL)
	if err != nil {
		return err
	}
	authURL, err := buildAuthorizationURL(as, cc, pkce, state, resourceURL, spendToken)
	if err != nil {
		return err
	}
	// ATXP deviation: sign the code_challenge with the account and present it as a
	// Bearer JWT on a server-to-server authorization GET.
	jwt, err := c.account.SignChallenge(ctx, pkce.CodeChallenge)
	if err != nil {
		return err
	}
	redirectURL, err := c.requestAuthorizationCode(ctx, authURL, jwt)
	if err != nil {
		return err
	}
	code, gotState, err := parseCallback(redirectURL)
	if err != nil {
		return err
	}
	stored, ok := c.store.GetPKCE(c.userID, gotState)
	if !ok {
		return fmt.Errorf("no PKCE values for state %q", gotState)
	}
	tok, err := c.exchangeCode(ctx, as, cc, code, stored.CodeVerifier)
	if err != nil {
		return err
	}
	tok.ResourceURL = resourceURL
	c.store.SaveAccessToken(c.userID, resourceURL, tok)
	return nil
}

// requestAuthorizationCode performs the ATXP authorization GET and extracts the
// callback URL. ATXP servers return either a 3xx with a Location header, or
// (the redirect=false hack) a 200 with {"redirect": "<callback>"} in the body.
func (c *oauthClient) requestAuthorizationCode(ctx context.Context, authURL, jwt string) (string, error) {
	sep := "?"
	if strings.Contains(authURL, "?") {
		sep = "&"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, authURL+sep+"redirect=false", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+jwt)

	// Do not follow redirects: we want the Location, not its target.
	noFollow := *c.http
	noFollow.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := noFollow.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		if loc := resp.Header.Get("Location"); loc != "" {
			return loc, nil
		}
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		var b struct {
			Redirect string `json:"redirect"`
		}
		if err := json.Unmarshal(body, &b); err == nil && b.Redirect != "" {
			return b.Redirect, nil
		}
	}
	return "", fmt.Errorf("authorization request: expected redirect, got status %d: %s", resp.StatusCode, body)
}

// parseCallback extracts the authorization code and state from a callback URL.
func parseCallback(raw string) (code, state string, err error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", err
	}
	q := u.Query()
	code = q.Get("code")
	state = q.Get("state")
	if code == "" {
		return "", "", fmt.Errorf("callback URL missing code: %s", raw)
	}
	return code, state, nil
}

func randomURLSafe(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

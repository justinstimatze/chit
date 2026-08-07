package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"

	atxp "github.com/justinstimatze/chit"
)

// Resource-server OAuth. Ported from @atxp/common OAuthResourceClient (the parts
// the merchant side uses): dynamic client registration of the merchant's own
// "server" client, and RFC 7662 token introspection of a caller's bearer token.
//
// The merchant registers once with the authorization server (DCR), storing the
// resulting client_id/secret keyed by the AS issuer. Those credentials then
// authenticate both the introspection calls here and the /charge calls in
// paymentserver.go.

// authServerMeta is the subset of RFC 8414 authorization-server metadata used.
type authServerMeta struct {
	Issuer                string `json:"issuer"`
	RegistrationEndpoint  string `json:"registration_endpoint"`
	IntrospectionEndpoint string `json:"introspection_endpoint"`
}

// TokenData is the RFC 7662 introspection result. Ported from @atxp/common
// TokenData. `Exp` is a Unix timestamp in SECONDS when the AS provides it.
type TokenData struct {
	Active bool          `json:"active"`
	Scope  string        `json:"scope,omitempty"`
	Sub    string        `json:"sub,omitempty"`
	Aud    stringOrSlice `json:"aud,omitempty"`
	Exp    int64         `json:"exp,omitempty"`
}

// stringOrSlice decodes a JSON field that may be either a string or an array of
// strings (RFC 7662 `aud` is allowed to be either).
type stringOrSlice []string

func (s *stringOrSlice) UnmarshalJSON(b []byte) error {
	if len(b) == 0 || string(b) == "null" {
		return nil
	}
	if b[0] == '[' {
		var arr []string
		if err := json.Unmarshal(b, &arr); err != nil {
			return err
		}
		*s = arr
		return nil
	}
	var one string
	if err := json.Unmarshal(b, &one); err != nil {
		return err
	}
	*s = []string{one}
	return nil
}

func (s stringOrSlice) contains(v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// resourceClient performs DCR + introspection against authorization servers.
type resourceClient struct {
	store           atxp.Store
	http            *http.Client
	connectionToken string // merchant's ATXP connection token; wallet-grade, never logged
	clientName      string
	allowHTTP       bool
	logger          Logger

	mu      sync.Mutex
	meta    map[string]authServerMeta    // authServer base URL -> discovered metadata
	credReg map[string]*credRegistration // issuer -> in-flight/just-finished DCR call
}

// credRegistration coordinates concurrent clientCredentials callers for the
// same issuer so only one dynamic-client-registration HTTP call is ever in
// flight at a time. Without this, concurrent callers (e.g. several inbound
// requests hitting the merchant before its first credentials are cached)
// each independently call POST /register; some auth servers reject a second
// near-simultaneous registration for the same connection token with 409,
// and that caller's error propagated even though a sibling call's
// registration succeeded moments earlier — a real, observed failure mode,
// not hypothetical.
type credRegistration struct {
	done chan struct{}
	cc   atxp.ClientCredentials
	err  error
}

func newResourceClient(store atxp.Store, hc *http.Client, connectionToken, clientName string, allowHTTP bool, logger Logger) *resourceClient {
	return &resourceClient{
		store:           store,
		http:            hc,
		connectionToken: connectionToken,
		clientName:      clientName,
		allowHTTP:       allowHTTP,
		logger:          logger,
		meta:            map[string]authServerMeta{},
		credReg:         map[string]*credRegistration{},
	}
}

// discover fetches and caches the AS metadata for an authorization server.
func (c *resourceClient) discover(ctx context.Context, authServer string) (authServerMeta, error) {
	c.mu.Lock()
	if m, ok := c.meta[authServer]; ok {
		c.mu.Unlock()
		return m, nil
	}
	c.mu.Unlock()

	if err := c.checkScheme(authServer); err != nil {
		return authServerMeta{}, err
	}
	disco, err := url.JoinPath(authServer, "/.well-known/oauth-authorization-server")
	if err != nil {
		return authServerMeta{}, err
	}
	status, body, err := c.get(ctx, disco)
	if err != nil {
		return authServerMeta{}, fmt.Errorf("atxp server: AS discovery %s: %w", disco, err)
	}
	if status != http.StatusOK {
		return authServerMeta{}, fmt.Errorf("atxp server: AS discovery %s: status %d", disco, status)
	}
	var m authServerMeta
	if err := json.Unmarshal(body, &m); err != nil {
		return authServerMeta{}, fmt.Errorf("atxp server: decode AS metadata: %w", err)
	}
	if m.Issuer == "" {
		m.Issuer = strings.TrimRight(authServer, "/")
	}
	c.mu.Lock()
	c.meta[authServer] = m
	c.mu.Unlock()
	return m, nil
}

// clientCredentials returns the merchant's DCR credentials for an authorization
// server, registering on first use. Implements credentialsSource. Concurrent
// callers for the same issuer share a single in-flight registration (see
// credRegistration) rather than each independently racing POST /register.
func (c *resourceClient) clientCredentials(ctx context.Context, authServer string) (clientID, clientSecret string, err error) {
	m, err := c.discover(ctx, authServer)
	if err != nil {
		return "", "", err
	}
	if cc, ok := c.store.GetClientCredentials(m.Issuer); ok {
		return cc.ClientID, cc.ClientSecret, nil
	}

	c.mu.Lock()
	if reg, ok := c.credReg[m.Issuer]; ok {
		c.mu.Unlock()
		<-reg.done
		if reg.err != nil {
			return "", "", reg.err
		}
		return reg.cc.ClientID, reg.cc.ClientSecret, nil
	}
	reg := &credRegistration{done: make(chan struct{})}
	c.credReg[m.Issuer] = reg
	c.mu.Unlock()

	cc, regErr := c.registerClient(ctx, m)
	reg.cc, reg.err = cc, regErr
	close(reg.done)

	c.mu.Lock()
	delete(c.credReg, m.Issuer) // let a later, non-concurrent call retry if this one failed
	c.mu.Unlock()

	if regErr != nil {
		return "", "", regErr
	}
	c.store.SaveClientCredentials(m.Issuer, cc)
	return cc.ClientID, cc.ClientSecret, nil
}

// registerClient performs RFC 7591 dynamic client registration as a "server"
// client. Ported from OAuthResourceClient.registerClient.
func (c *resourceClient) registerClient(ctx context.Context, m authServerMeta) (atxp.ClientCredentials, error) {
	if m.RegistrationEndpoint == "" {
		return atxp.ClientCredentials{}, fmt.Errorf("atxp server: AS %s does not support dynamic client registration", m.Issuer)
	}
	clientName := c.clientName
	if clientName == "" {
		clientName = "chit ATXP merchant"
	}
	meta := map[string]any{
		"redirect_uris":              []string{"http://localhost:3000/unused-dummy-global-callback"},
		"response_types":             []string{"code"},
		"grant_types":                []string{"authorization_code", "client_credentials"},
		"token_endpoint_auth_method": "client_secret_basic",
		"client_name":                clientName,
	}
	buf, _ := json.Marshal(meta)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.RegistrationEndpoint, strings.NewReader(string(buf)))
	if err != nil {
		return atxp.ClientCredentials{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-ATXP-Registration-Type", "server")
	if c.connectionToken != "" {
		req.Header.Set("X-ATXP-TOKEN", c.connectionToken)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return atxp.ClientCredentials{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return atxp.ClientCredentials{}, fmt.Errorf("atxp server: client registration failed: status %d", resp.StatusCode)
	}
	var reg struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	if err := json.Unmarshal(body, &reg); err != nil {
		return atxp.ClientCredentials{}, fmt.Errorf("atxp server: decode registration: %w", err)
	}
	if reg.ClientID == "" {
		return atxp.ClientCredentials{}, fmt.Errorf("atxp server: registration returned no client_id")
	}
	return atxp.ClientCredentials{ClientID: reg.ClientID, ClientSecret: reg.ClientSecret}, nil
}

// introspectToken validates a caller's bearer token via RFC 7662 introspection.
// Ported from OAuthResourceClient.introspectToken, including the
// re-register-and-retry on 401/403 (stale client credentials).
func (c *resourceClient) introspectToken(ctx context.Context, authServer, token string) (TokenData, error) {
	m, err := c.discover(ctx, authServer)
	if err != nil {
		return TokenData{}, err
	}
	if m.IntrospectionEndpoint == "" {
		return TokenData{}, fmt.Errorf("atxp server: AS %s does not advertise an introspection_endpoint", m.Issuer)
	}
	clientID, clientSecret, err := c.clientCredentials(ctx, authServer)
	if err != nil {
		return TokenData{}, err
	}

	status, body, err := c.introspectOnce(ctx, m.IntrospectionEndpoint, clientID, clientSecret, token)
	if err != nil {
		return TokenData{}, err
	}
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		// Client credentials may be stale; re-register once and retry.
		c.logger.Infof("introspection got %d, re-registering client", status)
		cc, regErr := c.registerClient(ctx, m)
		if regErr != nil {
			return TokenData{}, regErr
		}
		c.store.SaveClientCredentials(m.Issuer, cc)
		status, body, err = c.introspectOnce(ctx, m.IntrospectionEndpoint, cc.ClientID, cc.ClientSecret, token)
		if err != nil {
			return TokenData{}, err
		}
	}
	if status != http.StatusOK {
		return TokenData{}, fmt.Errorf("atxp server: token introspection failed with status %d", status)
	}
	var td TokenData
	if err := json.Unmarshal(body, &td); err != nil {
		return TokenData{}, fmt.Errorf("atxp server: decode introspection response: %w", err)
	}
	return td, nil
}

func (c *resourceClient) introspectOnce(ctx context.Context, endpoint, clientID, clientSecret, token string) (int, []byte, error) {
	form := url.Values{}
	form.Set("token", token)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", basicAuth(clientID, clientSecret))
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("atxp server: introspection request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *resourceClient) get(ctx context.Context, u string) (int, []byte, error) {
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

// checkScheme enforces HTTPS for authorization servers unless AllowHTTP was set
// (intended only for local development and tests). Sending DCR requests — which
// carry the merchant's connection token — over plaintext would leak it.
func (c *resourceClient) checkScheme(rawURL string) error {
	if c.allowHTTP {
		return nil
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("atxp server: parse auth server url: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("atxp server: refusing to talk to non-HTTPS authorization server %q (set AllowHTTP for local dev)", rawURL)
	}
	return nil
}

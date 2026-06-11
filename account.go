// Package atxp is a client for paid ATXP MCP tools (web search, image/video/music
// generation, etc.) using a hosted ATXP account (a connection string).
//
// gemot uses ATXP only as a paid-tool rail; LLM inference stays on the native
// Anthropic SDK. The hosted-account model means this client performs no on-chain
// crypto: every signing and settlement operation is an HTTP call to the ATXP
// accounts server. See ATXP_GO_HANDOFF.md for the full protocol, with file:line
// references into the reference TypeScript SDK (github.com/atxp-dev/sdk).
//
// The shape mirrors the TS @atxp/client: an http.RoundTripper (transport.go)
// wraps an MCP Streamable HTTP transport and transparently handles the two legs
// of the protocol — OAuth authentication (oauth.go) and payment challenges
// (account.Authorize → the accounts server's /authorize/auto).
package atxp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// Account is the credential + payment backend the transport delegates to.
// Only the hosted ATXPAccount is implemented; the interface keeps the transport
// decoupled from it (and leaves room for a future self-custodial account).
type Account interface {
	// AccountID returns the qualified account id ("atxp:<id>"), fetching it from
	// the accounts server's /me endpoint if it was not in the connection string.
	AccountID(ctx context.Context) (string, error)
	// SignChallenge asks the accounts server to mint the JWT that authorizes the
	// OAuth /authorize GET, binding the PKCE code_challenge to this account.
	SignChallenge(ctx context.Context, codeChallenge string) (jwt string, err error)
	// SpendPermission pre-authorizes spending for an MCP server during OAuth.
	// Returns "" (no error) if the account type does not support it.
	SpendPermission(ctx context.Context, resourceURL string) (token string, err error)
	// Authorize settles a payment challenge via /authorize/auto and returns the
	// protocol + opaque credential to attach to the retried request.
	Authorize(ctx context.Context, p AuthorizeParams) (AuthorizeResult, error)
}

// AuthorizeParams is the payment-challenge data sent to /authorize/auto.
type AuthorizeParams struct {
	Protocols           []string        // "atxp", and optionally "x402"/"mpp"
	Amount              string          // decimal string, e.g. "0.01"
	Destination         string          // receiver address (maps to "receiver")
	Memo                string          // issuer / payee name
	PaymentRequirements json.RawMessage // x402 { x402Version, accepts } if present
	Challenges          json.RawMessage // mpp challenges array if present
}

// AuthorizeResult is the credential returned by /authorize/auto.
type AuthorizeResult struct {
	Protocol   string          `json:"protocol"` // "atxp" | "x402" | "mpp"
	Credential string          `json:"credential"`
	Context    json.RawMessage `json:"context,omitempty"`
}

// RestrictionError is returned when the accounts server rejects an operation
// because the account is restricted (e.g. a fresh, unverified account is
// "fraud_blocked" until a payment method is added). It is environmental, not a
// client bug: the request was well-formed and the server processed it.
type RestrictionError struct {
	Op      string // the operation, e.g. "/sign"
	Code    string // restriction.error, e.g. "fraud_blocked"
	Message string // human-readable restriction.message
}

func (e *RestrictionError) Error() string {
	return fmt.Sprintf("atxp: %s rejected — account restricted (%s): %s", e.Op, e.Code, e.Message)
}

// restriction is the rejection envelope returned by accounts-server endpoints.
type restriction struct {
	Rejected    bool `json:"rejected"`
	Restriction struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	} `json:"restriction"`
}

func (r restriction) asError(op string) error {
	if !r.Rejected {
		return nil
	}
	return &RestrictionError{Op: op, Code: r.Restriction.Error, Message: r.Restriction.Message}
}

// ATXPAccount is a hosted account identified by a connection string of the form
//
//	https://accounts.atxp.ai/?connection_token=<TOKEN>&account_id=<ID>
//
// account_id is optional and resolved from /me on first use.
type ATXPAccount struct {
	origin string
	token  string
	http   *http.Client

	mu             sync.Mutex
	accountID      string // qualified "atxp:<id>"
	rawAccountID   string // unqualified
	accountIDReady bool
}

// NewATXPAccount parses a connection string into a hosted account. The http
// client is used for all accounts-server calls; pass nil for http.DefaultClient.
func NewATXPAccount(connectionString string, hc *http.Client) (*ATXPAccount, error) {
	cs := connectionString
	if cs == "" {
		return nil, fmt.Errorf("atxp: connection string is empty")
	}
	u, err := url.Parse(cs)
	if err != nil {
		return nil, fmt.Errorf("atxp: invalid connection string: %w", err)
	}
	token := u.Query().Get("connection_token")
	if token == "" {
		return nil, fmt.Errorf("atxp: connection string missing connection_token")
	}
	if hc == nil {
		hc = &http.Client{Timeout: 65 * time.Second}
	}
	a := &ATXPAccount{
		origin: u.Scheme + "://" + u.Host,
		token:  token,
		http:   hc,
	}
	if id := u.Query().Get("account_id"); id != "" {
		a.rawAccountID = id
		a.accountID = "atxp:" + id
		a.accountIDReady = true
	}
	return a, nil
}

// Origin is the accounts-server base URL (e.g. https://accounts.atxp.ai).
func (a *ATXPAccount) Origin() string { return a.origin }

// basicAuth returns the "Basic base64(token:)" header value used by /sign,
// /authorize/auto, /pay and /address_for_payment (blank password).
func (a *ATXPAccount) basicAuth() string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(a.token+":"))
}

// bearerAuth returns the "Bearer <token>" value used by /me and /spend-permission.
func (a *ATXPAccount) bearerAuth() string { return "Bearer " + a.token }

func (a *ATXPAccount) AccountID(ctx context.Context) (string, error) {
	a.mu.Lock()
	if a.accountIDReady {
		id := a.accountID
		a.mu.Unlock()
		return id, nil
	}
	a.mu.Unlock()

	var body struct {
		AccountID string `json:"accountId"`
	}
	if err := a.getJSON(ctx, a.origin+"/me", a.bearerAuth(), &body); err != nil {
		return "", fmt.Errorf("atxp: /me: %w", err)
	}
	if body.AccountID == "" {
		return "", fmt.Errorf("atxp: /me did not return accountId")
	}
	a.mu.Lock()
	a.rawAccountID = body.AccountID
	a.accountID = "atxp:" + body.AccountID
	a.accountIDReady = true
	a.mu.Unlock()
	return a.accountID, nil
}

func (a *ATXPAccount) SignChallenge(ctx context.Context, codeChallenge string) (string, error) {
	req := map[string]any{
		"paymentRequestId": "",
		"codeChallenge":    codeChallenge,
	}
	a.mu.Lock()
	if a.rawAccountID != "" {
		req["accountId"] = a.rawAccountID
	}
	a.mu.Unlock()

	var out struct {
		JWT string `json:"jwt"`
		restriction
	}
	if err := a.postJSON(ctx, a.origin+"/sign", a.basicAuth(), req, &out); err != nil {
		return "", fmt.Errorf("atxp: /sign: %w", err)
	}
	if err := out.asError("/sign"); err != nil {
		return "", err
	}
	if out.JWT == "" {
		return "", fmt.Errorf("atxp: /sign did not return jwt")
	}
	return out.JWT, nil
}

func (a *ATXPAccount) SpendPermission(ctx context.Context, resourceURL string) (string, error) {
	var out struct {
		SpendPermissionToken string `json:"spendPermissionToken"`
	}
	err := a.postJSON(ctx, a.origin+"/spend-permission", a.bearerAuth(),
		map[string]any{"resourceUrl": resourceURL}, &out)
	if err != nil {
		return "", fmt.Errorf("atxp: /spend-permission: %w", err)
	}
	return out.SpendPermissionToken, nil
}

func (a *ATXPAccount) Authorize(ctx context.Context, p AuthorizeParams) (AuthorizeResult, error) {
	if len(p.Protocols) == 0 {
		return AuthorizeResult{}, fmt.Errorf("atxp: authorize: protocols must not be empty")
	}
	body := map[string]any{
		"protocols": p.Protocols,
		"currency":  "USDC",
	}
	if p.Amount != "" {
		body["amount"] = p.Amount
	}
	if p.Destination != "" {
		body["receiver"] = p.Destination
	}
	if p.Memo != "" {
		body["memo"] = p.Memo
	}
	if len(p.PaymentRequirements) > 0 {
		body["paymentRequirements"] = p.PaymentRequirements
	}
	if len(p.Challenges) > 0 {
		body["challenges"] = p.Challenges
	}

	var out struct {
		AuthorizeResult
		restriction
	}
	if err := a.postJSON(ctx, a.origin+"/authorize/auto", a.basicAuth(), body, &out); err != nil {
		return AuthorizeResult{}, fmt.Errorf("atxp: /authorize/auto: %w", err)
	}
	if err := out.asError("/authorize/auto"); err != nil {
		return AuthorizeResult{}, err
	}
	if out.Protocol == "" || out.Credential == "" {
		return AuthorizeResult{}, fmt.Errorf("atxp: /authorize/auto response missing protocol or credential")
	}
	// For the atxp protocol the credential is a JSON object; inject the
	// connection token so the credential is self-contained (mirrors the TS SDK).
	if out.Protocol == "atxp" {
		var obj map[string]any
		if err := json.Unmarshal([]byte(out.Credential), &obj); err == nil {
			a.mu.Lock()
			obj["sourceAccountToken"] = a.token
			a.mu.Unlock()
			if b, err := json.Marshal(obj); err == nil {
				out.Credential = string(b)
			}
		}
	}
	return out.AuthorizeResult, nil
}

// --- small JSON HTTP helpers -------------------------------------------------

func (a *ATXPAccount) getJSON(ctx context.Context, url, auth string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", auth)
	req.Header.Set("Accept", "application/json")
	return a.do(req, out)
}

func (a *ATXPAccount) postJSON(ctx context.Context, url, auth string, in, out any) error {
	buf, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", auth)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	return a.do(req, out)
}

func (a *ATXPAccount) do(req *http.Request, out any) error {
	resp, err := a.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("status %d: %s", resp.StatusCode, string(body))
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

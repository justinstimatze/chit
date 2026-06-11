package atxp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// MCP JSON-RPC error codes that signal "payment required". -30402 is the legacy
// ATXP code; -32042 is the newer omni/MPP code (also used by gemot's own server).
const (
	codePaymentRequiredLegacy = -30402
	codePaymentRequiredOmni   = -32042
)

// roundTripper wraps a base transport and transparently handles the ATXP
// protocol: OAuth authentication on 401, and payment settlement on an HTTP 402
// or an MCP JSON-RPC payment-required error embedded in a 200 response body.
//
// It mirrors the TS ATXPFetcher fetch wrapper (atxpFetcher.ts:845).
type roundTripper struct {
	base    http.RoundTripper
	account Account
	store   Store
	oauth   *oauthClient
}

func (rt *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	userID, err := rt.account.AccountID(ctx)
	if err != nil {
		return nil, fmt.Errorf("atxp: resolve account id: %w", err)
	}
	rt.oauth.userID = userID

	// Buffer the request body so the request can be replayed on retry.
	body, err := bufferBody(req)
	if err != nil {
		return nil, err
	}

	resp, err := rt.attempt(req, body, userID)
	if err != nil {
		return nil, err
	}

	// --- OAuth leg ---------------------------------------------------------
	if resp.StatusCode == http.StatusUnauthorized {
		resourceURL := resourceFromWWWAuthenticate(resp.Header.Get("WWW-Authenticate"))
		if resourceURL == "" {
			resourceURL = trimToPath(req.URL.String())
		}
		resp.Body.Close()
		if err := rt.oauth.authenticate(ctx, resourceURL); err != nil {
			return nil, fmt.Errorf("atxp: oauth: %w", err)
		}
		resp, err = rt.attempt(req, body, userID)
		if err != nil {
			return nil, err
		}
	}

	// --- payment leg -------------------------------------------------------
	pay, respBody, err := detectPayment(resp)
	if err != nil {
		return nil, err
	}
	if pay != nil {
		resp.Body.Close()
		if err := rt.settle(ctx, req, pay); err != nil {
			return nil, fmt.Errorf("atxp: payment: %w", err)
		}
		return rt.attempt(req, body, userID)
	}
	// Restore the (already-read) body for the caller.
	if respBody != nil {
		resp.Body = io.NopCloser(bytes.NewReader(respBody))
	}
	return resp, nil
}

// attempt issues one request with a fresh body and the current access token
// attached (unless an MPP "Authorization: Payment" header is already set).
func (rt *roundTripper) attempt(req *http.Request, body []byte, userID string) (*http.Response, error) {
	r := req.Clone(req.Context())
	if body != nil {
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
	}
	if existing := r.Header.Get("Authorization"); !strings.HasPrefix(existing, "Payment ") {
		if tok, ok := rt.store.GetAccessToken(userID, r.URL.String()); ok {
			r.Header.Set("Authorization", "Bearer "+tok.AccessToken)
		}
	}
	return rt.base.RoundTrip(r)
}

// settle handles a payment challenge via the accounts server and writes the
// resulting payment header onto req for the retry.
func (rt *roundTripper) settle(ctx context.Context, req *http.Request, pay *paymentChallenge) error {
	params, err := rt.buildAuthorizeParams(ctx, pay)
	if err != nil {
		return err
	}
	res, err := rt.account.Authorize(ctx, params)
	if err != nil {
		return err
	}
	applyPaymentHeader(req.Header, res)
	if pay.paymentRequestID != "" {
		req.Header.Set("X-ATXP-Payment-Request-Id", pay.paymentRequestID)
	}
	return nil
}

// buildAuthorizeParams maps challenge data to /authorize/auto params, fetching
// the payment request for a destination if necessary (mirrors buildAuthorizeParams
// in atxpAccountHandler.ts).
func (rt *roundTripper) buildAuthorizeParams(ctx context.Context, pay *paymentChallenge) (AuthorizeParams, error) {
	p := AuthorizeParams{Protocols: []string{"atxp"}, Memo: pay.memo}
	if pay.chargeAmount != "" {
		p.Amount = pay.chargeAmount
	}
	if len(pay.x402) > 0 {
		p.PaymentRequirements = pay.x402
		p.Protocols = append(p.Protocols, "x402")
		if d, a := firstX402(pay.x402); d != "" {
			p.Destination = d
			if p.Amount == "" {
				p.Amount = a
			}
		}
	}
	if len(pay.mpp) > 0 {
		p.Challenges = pay.mpp
		p.Protocols = append(p.Protocols, "mpp")
	}
	if p.Destination == "" && pay.paymentRequestURL != "" {
		if d, a := rt.fetchPaymentRequestDest(ctx, pay.paymentRequestURL); d != "" {
			p.Destination = d
			if p.Amount == "" {
				p.Amount = a
			}
		}
	}
	if p.Amount == "" {
		return AuthorizeParams{}, fmt.Errorf("payment challenge has no amount")
	}
	return p, nil
}

func (rt *roundTripper) fetchPaymentRequestDest(ctx context.Context, prURL string) (dest, amount string) {
	st, body, err := rt.oauth.get(ctx, prURL)
	if err != nil || st != http.StatusOK {
		return "", ""
	}
	var pr struct {
		Options []struct {
			Address string          `json:"address"`
			Amount  json.RawMessage `json:"amount"`
		} `json:"options"`
	}
	if err := json.Unmarshal(body, &pr); err != nil || len(pr.Options) == 0 {
		return "", ""
	}
	return pr.Options[0].Address, strings.Trim(string(pr.Options[0].Amount), `"`)
}

// applyPaymentHeader writes the protocol-specific payment header (paymentHeaders.ts).
func applyPaymentHeader(h http.Header, res AuthorizeResult) {
	switch res.Protocol {
	case "x402":
		h.Set("X-PAYMENT", res.Credential)
		h.Set("Access-Control-Expose-Headers", "X-PAYMENT-RESPONSE")
	case "mpp":
		h.Set("Authorization", "Payment "+res.Credential)
	case "atxp":
		h.Set("X-ATXP-PAYMENT", res.Credential)
	}
}

// paymentChallenge is the normalized payment-required signal from either an HTTP
// 402 or an MCP JSON-RPC error.
type paymentChallenge struct {
	chargeAmount      string
	memo              string
	x402              json.RawMessage
	mpp               json.RawMessage
	paymentRequestURL string
	paymentRequestID  string
}

// detectPayment inspects a response for a payment challenge. It returns the
// challenge (or nil) plus the response body it consumed so the caller can
// restore it when there is no challenge.
func detectPayment(resp *http.Response) (*paymentChallenge, []byte, error) {
	// Real HTTP 402.
	if resp.StatusCode == http.StatusPaymentRequired {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		pc := parseChallengeData(body)
		if pc == nil {
			pc = &paymentChallenge{} // 402 with no parseable data still triggers settle
		}
		return pc, body, nil
	}
	// MCP servers return 200 with the payment error inside the JSON-RPC body.
	ct := resp.Header.Get("Content-Type")
	if resp.StatusCode == http.StatusOK &&
		(strings.Contains(ct, "application/json") || strings.Contains(ct, "text/event-stream")) {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		pc := parseMCPPayment(ct, body)
		return pc, body, nil
	}
	return nil, nil, nil
}

// parseMCPPayment scans an MCP response (JSON or SSE) for a JSON-RPC payment
// error and extracts the challenge from error.data.
func parseMCPPayment(contentType string, body []byte) *paymentChallenge {
	var payloads [][]byte
	if strings.Contains(contentType, "text/event-stream") {
		for _, line := range strings.Split(string(body), "\n") {
			line = strings.TrimSpace(line)
			if data, ok := strings.CutPrefix(line, "data:"); ok {
				payloads = append(payloads, []byte(strings.TrimSpace(data)))
			}
		}
	} else {
		payloads = append(payloads, body)
	}
	for _, p := range payloads {
		var msg struct {
			Error *struct {
				Code int             `json:"code"`
				Data json.RawMessage `json:"data"`
			} `json:"error"`
		}
		if err := json.Unmarshal(p, &msg); err != nil || msg.Error == nil {
			continue
		}
		if msg.Error.Code != codePaymentRequiredLegacy && msg.Error.Code != codePaymentRequiredOmni {
			continue
		}
		if pc := parseChallengeData(msg.Error.Data); pc != nil {
			return pc
		}
		return &paymentChallenge{}
	}
	return nil
}

// parseChallengeData reads the common challenge fields out of an error.data /
// 402-body object.
func parseChallengeData(data []byte) *paymentChallenge {
	if len(data) == 0 {
		return nil
	}
	var d struct {
		ChargeAmount      json.RawMessage `json:"chargeAmount"`
		PayeeName         string          `json:"payeeName"`
		Iss               string          `json:"iss"`
		X402              json.RawMessage `json:"x402"`
		MPP               json.RawMessage `json:"mpp"`
		PaymentRequestURL string          `json:"paymentRequestUrl"`
		PaymentRequestID  string          `json:"paymentRequestId"`
	}
	if err := json.Unmarshal(data, &d); err != nil {
		return nil
	}
	pc := &paymentChallenge{
		chargeAmount:      strings.Trim(string(d.ChargeAmount), `"`),
		memo:              firstNonEmpty(d.Iss, d.PayeeName),
		x402:              nonEmptyJSON(d.X402),
		mpp:               nonEmptyJSON(d.MPP),
		paymentRequestURL: d.PaymentRequestURL,
		paymentRequestID:  d.PaymentRequestID,
	}
	if pc.chargeAmount == "" && pc.x402 == nil && pc.mpp == nil &&
		pc.paymentRequestURL == "" && pc.paymentRequestID == "" {
		return nil
	}
	return pc
}

// firstX402 pulls a destination (payTo) and amount from the first non-atxp entry
// of an x402 { accepts: [...] } object.
func firstX402(raw json.RawMessage) (dest, amount string) {
	var x struct {
		Accepts []struct {
			Network string          `json:"network"`
			PayTo   string          `json:"payTo"`
			Amount  json.RawMessage `json:"amount"`
		} `json:"accepts"`
	}
	if err := json.Unmarshal(raw, &x); err != nil {
		return "", ""
	}
	for _, a := range x.Accepts {
		if a.Network == "atxp" {
			continue
		}
		return a.PayTo, strings.Trim(string(a.Amount), `"`)
	}
	return "", ""
}

func bufferBody(req *http.Request) ([]byte, error) {
	if req.Body == nil {
		return nil, nil
	}
	b, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	req.Body.Close()
	req.Body = io.NopCloser(bytes.NewReader(b))
	return b, nil
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}

func nonEmptyJSON(r json.RawMessage) json.RawMessage {
	s := strings.TrimSpace(string(r))
	if s == "" || s == "null" {
		return nil
	}
	return r
}

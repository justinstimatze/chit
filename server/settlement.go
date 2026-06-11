package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// Protocol settlement. Ported from protocol.ts ProtocolSettlement — the client
// for the authorization server's /verify/{protocol} and /settle/{protocol}
// endpoints, used on the push-payment retry path (x402 / MPP / ATXP credentials
// presented on the second request).
//
// The credential is self-authenticating, so (matching the TS reference) these
// calls carry no client-credential Basic auth — only Content-Type and an
// optional X-ATXP-APP-NAME observability header.

const appNameHeader = "X-ATXP-APP-NAME"

// appNameRe matches the auth-side accepted format; values outside it are dropped
// by the receiver, so we omit them rather than send something that will vanish.
var appNameRe = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,64}$`)

// SettlementContext carries the data verify/settle need to build protocol bodies.
// Ported from protocol.ts SettlementContext.
type SettlementContext struct {
	PaymentRequirements  *X402PaymentRequirements
	PaymentRequestID     string
	SourceAccountID      string
	DestinationAccountID string
	Options              any
}

// VerifyResult is the /verify response. Ported from protocol.ts VerifyResult.
type VerifyResult struct {
	Valid bool `json:"valid"`
}

// SettleResult is the /settle response. TxHash is nil when the payment was
// already settled by a prior call. Ported from protocol.ts SettleResult.
type SettleResult struct {
	TxHash         *string `json:"txHash"`
	SettledAmount  string  `json:"settledAmount"`
	AlreadySettled bool    `json:"alreadySettled,omitempty"`
}

// ProtocolSettlement calls the AS verify/settle endpoints. Ported from
// protocol.ts ProtocolSettlement.
type ProtocolSettlement struct {
	authServer           string
	http                 *http.Client
	destinationAccountID string
	appName              string
	logger               Logger
}

func newProtocolSettlement(authServer string, hc *http.Client, destinationAccountID, appName string, logger Logger) *ProtocolSettlement {
	if appName != "" && !appNameRe.MatchString(appName) {
		appName = "" // would be dropped by auth anyway; omit cleanly
	}
	return &ProtocolSettlement{
		authServer:           authServer,
		http:                 hc,
		destinationAccountID: destinationAccountID,
		appName:              appName,
		logger:               logger,
	}
}

func (p *ProtocolSettlement) headers() http.Header {
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	if p.appName != "" {
		h.Set(appNameHeader, p.appName)
	}
	return h
}

// Verify checks a payment credential at request start. Returns {valid:false} on
// any non-2xx response — fail closed. Ported from ProtocolSettlement.verify.
func (p *ProtocolSettlement) Verify(ctx context.Context, protocol Protocol, credential string, sctx *SettlementContext) (VerifyResult, error) {
	body, err := p.buildRequestBody(protocol, credential, sctx)
	if err != nil {
		return VerifyResult{}, err
	}
	status, respBody, err := p.post(ctx, "/verify/"+string(protocol), body)
	if err != nil {
		return VerifyResult{}, err
	}
	if status < 200 || status >= 300 {
		p.logger.Warnf("verify %s failed with status %d", protocol, status)
		return VerifyResult{Valid: false}, nil
	}
	var out VerifyResult
	if err := json.Unmarshal(respBody, &out); err != nil {
		return VerifyResult{}, fmt.Errorf("atxp server: decode verify response: %w", err)
	}
	return out, nil
}

// Settle finalizes a payment at request end. A non-2xx response is an error (the
// payment did not settle). Ported from ProtocolSettlement.settle.
func (p *ProtocolSettlement) Settle(ctx context.Context, protocol Protocol, credential string, sctx *SettlementContext) (SettleResult, error) {
	body, err := p.buildRequestBody(protocol, credential, sctx)
	if err != nil {
		return SettleResult{}, err
	}
	status, respBody, err := p.post(ctx, "/settle/"+string(protocol), body)
	if err != nil {
		return SettleResult{}, err
	}
	if status < 200 || status >= 300 {
		p.logger.Errorf("settle %s failed with status %d", protocol, status)
		return SettleResult{}, fmt.Errorf("atxp server: settlement failed for %s: status %d", protocol, status)
	}
	var out SettleResult
	if err := json.Unmarshal(respBody, &out); err != nil {
		return SettleResult{}, fmt.Errorf("atxp server: decode settle response: %w", err)
	}
	return out, nil
}

func (p *ProtocolSettlement) post(ctx context.Context, path string, body any) (int, []byte, error) {
	endpoint, err := url.JoinPath(p.authServer, path)
	if err != nil {
		return 0, nil, err
	}
	buf, err := json.Marshal(body)
	if err != nil {
		return 0, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(buf))
	if err != nil {
		return 0, nil, err
	}
	req.Header = p.headers()
	resp, err := p.http.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("atxp server: POST %s: %w", path, err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, respBody, nil
}

// buildRequestBody builds the protocol-specific verify/settle body. Ported from
// ProtocolSettlement.buildRequestBody.
func (p *ProtocolSettlement) buildRequestBody(protocol Protocol, credential string, sctx *SettlementContext) (map[string]any, error) {
	if sctx == nil {
		sctx = &SettlementContext{}
	}
	switch protocol {
	case ProtocolX402:
		var payload any = parseCredentialJSON(credential)
		if payload == nil {
			payload = map[string]any{"raw": credential}
		}
		requirements := p.selectX402Requirement(payload, sctx.PaymentRequirements)
		out := map[string]any{"payload": payload}
		if requirements != nil {
			out["paymentRequirements"] = requirements
		}
		addIf(out, "paymentRequestId", sctx.PaymentRequestID)
		addIf(out, "sourceAccountId", sctx.SourceAccountID)
		addIf(out, "destinationAccountId", p.destinationAccountID)
		return out, nil

	case ProtocolMPP:
		parsed := parseCredentialJSON(credential)
		if parsed == nil {
			return nil, fmt.Errorf("atxp server: MPP credential is not valid base64 JSON or raw JSON")
		}
		out := map[string]any{"credential": parsed}
		addIf(out, "paymentRequestId", sctx.PaymentRequestID)
		addIf(out, "sourceAccountId", sctx.SourceAccountID)
		addIf(out, "destinationAccountId", p.destinationAccountID)
		return out, nil

	default: // ATXP
		var parsed map[string]any
		if err := json.Unmarshal([]byte(credential), &parsed); err != nil {
			p.logger.Warnf("ATXP credential is not valid JSON, using context fallback")
			parsed = map[string]any{}
		}
		var options any = sctx.Options
		if options == nil {
			options = parsed["options"]
		}
		if options == nil {
			options = []any{}
		}
		out := map[string]any{
			"sourceAccountId":      firstNonEmptyAny(parsed["sourceAccountId"], sctx.SourceAccountID),
			"destinationAccountId": firstNonEmptyStr(p.destinationAccountID, sctx.DestinationAccountID),
			"sourceAccountToken":   firstNonEmptyAny(parsed["sourceAccountToken"], credential),
			"options":              options,
		}
		addIf(out, "paymentRequestId", sctx.PaymentRequestID)
		return out, nil
	}
}

// selectX402Requirement picks the single accept matching the credential's chain
// from a full X402PaymentRequirements. Ported from the x402 branch of
// buildRequestBody.
func (p *ProtocolSettlement) selectX402Requirement(payload any, reqs *X402PaymentRequirements) any {
	if reqs == nil {
		return nil
	}
	accepts := reqs.Accepts
	if len(accepts) == 0 {
		return nil
	}
	acceptedNetwork := ""
	if obj, ok := payload.(map[string]any); ok {
		if acc, ok := obj["accepted"].(map[string]any); ok {
			if n, ok := acc["network"].(string); ok {
				acceptedNetwork = n
			}
		}
	}
	if acceptedNetwork != "" {
		for _, a := range accepts {
			if a.Network == acceptedNetwork {
				return a
			}
		}
		p.logger.Warnf("credential network %s not in accepts, using first accept", acceptedNetwork)
		return accepts[0]
	}
	for _, a := range accepts {
		if strings.HasPrefix(a.Network, "eip155") {
			return a
		}
	}
	p.logger.Warnf("no EVM accept found, using first accept")
	return accepts[0]
}

func addIf(m map[string]any, key, val string) {
	if val != "" {
		m[key] = val
	}
}

func firstNonEmptyAny(a any, fallback string) any {
	if s, ok := a.(string); ok && s != "" {
		return s
	}
	if a != nil {
		return a
	}
	return fallback
}

func firstNonEmptyStr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

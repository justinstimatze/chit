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
	body, err := p.buildRequestBody(protocol, credential, sctx, nil)
	if err != nil {
		return VerifyResult{}, err
	}
	status, respBody, err := p.post(ctx, "/verify/"+string(protocol), body)
	if err != nil {
		return VerifyResult{}, err
	}
	if status < 200 || status >= 300 {
		p.logger.Warnf("verify %s failed with status %d body=%s", protocol, status, string(respBody))
		return VerifyResult{Valid: false}, nil
	}
	var out VerifyResult
	if err := json.Unmarshal(respBody, &out); err != nil {
		return VerifyResult{}, fmt.Errorf("atxp server: decode verify response: %w", err)
	}
	return out, nil
}

// Settle finalizes a payment at request end. A non-2xx response is an error (the
// payment did not settle). actualAmount, when non-nil, is the metered "up-to"
// amount actually spent (e.g. the sum of a PaymentSession's charges): for x402
// (upto scheme only) and MPP session credentials, this settles that actual
// amount (≤ the authorized cap) instead of the cap. nil settles the cap, as
// before. Ported from ProtocolSettlement.settle.
func (p *ProtocolSettlement) Settle(ctx context.Context, protocol Protocol, credential string, sctx *SettlementContext, actualAmount *Amount) (SettleResult, error) {
	body, err := p.buildRequestBody(protocol, credential, sctx, actualAmount)
	if err != nil {
		return SettleResult{}, err
	}
	status, respBody, err := p.post(ctx, "/settle/"+string(protocol), body)
	if err != nil {
		return SettleResult{}, err
	}
	if status < 200 || status >= 300 {
		p.logger.Errorf("settle %s failed with status %d body=%s", protocol, status, string(respBody))
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
	defer func() { _ = resp.Body.Close() }()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, respBody, nil
}

// buildRequestBody builds the protocol-specific verify/settle body. actualAmount
// is the metered "up-to" amount (nil for verify, or for a settle carrying no
// session). Ported from ProtocolSettlement.buildRequestBody.
func (p *ProtocolSettlement) buildRequestBody(protocol Protocol, credential string, sctx *SettlementContext, actualAmount *Amount) (map[string]any, error) {
	if sctx == nil {
		sctx = &SettlementContext{}
	}
	switch protocol {
	case ProtocolX402:
		payload := parseCredentialJSON(credential)
		if payload == nil {
			payload = map[string]any{"raw": credential}
		}
		requirement := selectX402Accept(payload, sctx.PaymentRequirements, p.logger)
		out := map[string]any{"payload": payload}
		if requirement != nil {
			out["paymentRequirements"] = requirement
		}

		// "up-to" semantics: settle the metered actual (≤ the Permit2 cap) via
		// settlementOverrides.amount, in atomic micro-USDC. ONLY for the
		// 'upto' scheme — 'exact'/EIP-3009 commits the signature to a fixed
		// value, so overriding it would mismatch the signed authorization and
		// the facilitator would reject it. Clamp to the cap: a meter overshoot
		// must collect the cap, not revert the whole settle.
		if actualAmount != nil && requirement != nil && requirement.Scheme == "upto" {
			settleAmount := *actualAmount
			if cap, err := AmountFromMicroString(requirement.Amount); err == nil {
				settleAmount = Min(settleAmount, cap)
			}
			out["settlementOverrides"] = map[string]any{"amount": settleAmount.MicroString()}
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

		// "up-to" semantics for TIP-1034 session credentials only: settle the
		// metered actual (≤ the channel deposit) via settlementOverrides.amount
		// in raw atomic µUSDC. The one-shot `charge` path ignores actualAmount
		// and settles the pre-signed transfer as-is.
		if actualAmount != nil && isMppSessionCredential(credential) {
			out["settlementOverrides"] = map[string]any{"amount": actualAmount.MicroString()}
		}

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
		var options = sctx.Options
		if options == nil {
			options = parsed["options"]
		}
		if options == nil {
			options = []any{}
		}

		// "up-to" semantics: when an actual metered amount is supplied, settle
		// that (≤ the authorized cap) instead of the cap baked into each
		// option, so /pay charges the actual.
		if actualAmount != nil {
			options = overrideOptionsAmount(options, actualAmount.String(), p.logger)
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

// overrideOptionsAmount returns options with every entry's "amount" field
// replaced by amount. options is typically []any of map[string]any (as
// produced by json.Unmarshal), but SettlementContext.Options is declared as
// any specifically so a caller can supply a concretely-typed slice instead —
// so this normalizes via a JSON round-trip rather than asserting []any
// directly, which would otherwise silently no-op (settling the credential's
// full cap instead of the metered actual) for any other slice shape.
// On any marshal/unmarshal failure it logs a warning and returns options
// unchanged, so the settle body still carries a value rather than erroring.
func overrideOptionsAmount(options any, amount string, logger Logger) any {
	buf, err := json.Marshal(options)
	if err != nil {
		logger.Warnf("overrideOptionsAmount: marshal options: %v; settling the credential cap, not the actual", err)
		return options
	}
	var arr []map[string]any
	if err := json.Unmarshal(buf, &arr); err != nil {
		logger.Warnf("overrideOptionsAmount: options is not an array of objects: %v; settling the credential cap, not the actual", err)
		return options
	}
	out := make([]any, len(arr))
	for i, m := range arr {
		m["amount"] = amount
		out[i] = m
	}
	return out
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

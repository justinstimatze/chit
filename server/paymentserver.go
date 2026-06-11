package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// chargeOptionWire is one network option inside a /charge or /payment-request
// body. The amount is a decimal USDC string — the JSON form a BigNumber takes
// in the TS SDK (BigNumber.toJSON()).
type chargeOptionWire struct {
	Network  string `json:"network"`
	Currency string `json:"currency"`
	Address  string `json:"address"`
	Amount   string `json:"amount"`
}

// ChargeRequest is the body for POST /charge and POST /payment-request. Ported
// from the @atxp/server Charge type. When talking to the authorization server
// the merchant does not send resource/resourceName — the AS already knows them
// and must not trust the merchant to self-report them.
type ChargeRequest struct {
	Options              []chargeOptionWire `json:"options"`
	SourceAccountID      string             `json:"sourceAccountId"`
	DestinationAccountID string             `json:"destinationAccountId"`
	PayeeName            string             `json:"payeeName"`
	// SourceAccountToken is the caller's OAuth/connection token for on-demand
	// (pull-mode) charging. Wallet-grade; never logged.
	SourceAccountToken string `json:"sourceAccountToken,omitempty"`
	// PaymentRequestID ties /settle and the follow-up /charge to one payment.
	PaymentRequestID string `json:"paymentRequestId,omitempty"`
}

// BalanceRequest is the body for POST /balance. Ported from @atxp/server.
type BalanceRequest struct {
	SourceAccountID      string `json:"sourceAccountId"`
	DestinationAccountID string `json:"destinationAccountId"`
	SourceAccountToken   string `json:"sourceAccountToken,omitempty"`
}

// PaymentServer is the merchant's HTTP client to the ATXP authorization server's
// money endpoints. Ported from the @atxp/server PaymentServer interface.
//
// All settlement is delegated to the AS over HTTP; chit performs no on-chain
// crypto here. Charge reports whether the pull-mode charge settled.
type PaymentServer interface {
	// Charge attempts an on-demand pull. Returns true when the charge settled
	// (HTTP 200 or 202), false when payment is still required (HTTP 402), and a
	// non-nil error for every other outcome — including network failures — so a
	// caller that treats (false, nil) as "unpaid" never mistakes an
	// infrastructure error for a definite "unpaid".
	Charge(ctx context.Context, req ChargeRequest) (bool, error)
	// CreatePaymentRequest registers a payment request and returns its id.
	CreatePaymentRequest(ctx context.Context, req ChargeRequest) (string, error)
	// GetBalance returns the caller's available USDC balance.
	GetBalance(ctx context.Context, req BalanceRequest) (Amount, error)
}

// credentialsSource supplies the merchant's own dynamic-client-registration
// credentials for an authorization server, registering on first use. The
// resource-server OAuth client (oauthresource.go) implements it.
type credentialsSource interface {
	clientCredentials(ctx context.Context, authServer string) (clientID, clientSecret string, err error)
}

// ATXPPaymentServer talks to one authorization server. Ported from
// paymentServer.ts ATXPPaymentServer.
type ATXPPaymentServer struct {
	server string // authorization server base URL, e.g. https://auth.atxp.ai
	http   *http.Client
	creds  credentialsSource
	logger Logger
}

// newPaymentServer builds an ATXPPaymentServer. All fields are required.
func newPaymentServer(server string, hc *http.Client, creds credentialsSource, logger Logger) *ATXPPaymentServer {
	return &ATXPPaymentServer{server: server, http: hc, creds: creds, logger: logger}
}

// paymentServerError is the structured error body the AS returns on failure.
type paymentServerError struct {
	Error *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
	Message string `json:"message"`
}

func (e paymentServerError) describe() (code, message string) {
	code, message = "UNKNOWN_ERROR", "Unknown error"
	if e.Error != nil {
		if e.Error.Code != "" {
			code = e.Error.Code
		}
		if e.Error.Message != "" {
			message = e.Error.Message
		}
	} else if e.Message != "" {
		message = e.Message
	}
	return code, message
}

func (s *ATXPPaymentServer) Charge(ctx context.Context, req ChargeRequest) (bool, error) {
	status, body, err := s.makeRequest(ctx, "/charge", req)
	if err != nil {
		return false, err
	}
	switch status {
	case http.StatusOK, http.StatusAccepted: // 200 sync settle, 202 async accepted
		return true, nil
	case http.StatusPaymentRequired: // 402 — definitively unpaid
		return false, nil
	default:
		code, msg := decodeError(body)
		s.logger.Warnf("charge failed: status=%d code=%s msg=%s", status, code, msg)
		return false, fmt.Errorf("atxp server: /charge returned %d: %s (code %s)", status, msg, code)
	}
}

func (s *ATXPPaymentServer) CreatePaymentRequest(ctx context.Context, req ChargeRequest) (string, error) {
	status, body, err := s.makeRequest(ctx, "/payment-request", req)
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		code, msg := decodeError(body)
		s.logger.Warnf("payment-request failed: status=%d code=%s msg=%s", status, code, msg)
		return "", fmt.Errorf("atxp server: /payment-request returned %d: %s (code %s)", status, msg, code)
	}
	var out struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("atxp server: decode /payment-request: %w", err)
	}
	if out.ID == "" {
		return "", fmt.Errorf("atxp server: /payment-request response did not contain an id")
	}
	return out.ID, nil
}

func (s *ATXPPaymentServer) GetBalance(ctx context.Context, req BalanceRequest) (Amount, error) {
	status, body, err := s.makeRequest(ctx, "/balance", req)
	if err != nil {
		return Amount{}, err
	}
	if status != http.StatusOK {
		code, msg := decodeError(body)
		s.logger.Warnf("balance failed: status=%d code=%s msg=%s", status, code, msg)
		return Amount{}, fmt.Errorf("atxp server: /balance returned %d: %s (code %s)", status, msg, code)
	}
	var out struct {
		Balance *string `json:"balance"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return Amount{}, fmt.Errorf("atxp server: decode /balance: %w", err)
	}
	if out.Balance == nil {
		return Amount{}, fmt.Errorf("atxp server: /balance response did not contain a balance field")
	}
	amt, err := ParseAmount(*out.Balance)
	if err != nil {
		return Amount{}, fmt.Errorf("atxp server: /balance amount: %w", err)
	}
	return amt, nil
}

// makeRequest issues an authenticated POST to the authorization server. The
// merchant authenticates with HTTP Basic (clientId:clientSecret) from its DCR
// credentials, which lets the AS validate the resource_url binding.
//
// It returns the status code and the (size-limited) body. A non-2xx status is
// not itself an error here — each caller decides what each status means.
func (s *ATXPPaymentServer) makeRequest(ctx context.Context, path string, body any) (int, []byte, error) {
	endpoint, err := url.JoinPath(s.server, path)
	if err != nil {
		return 0, nil, fmt.Errorf("atxp server: build %s url: %w", path, err)
	}
	clientID, clientSecret, err := s.creds.clientCredentials(ctx, s.server)
	if err != nil {
		return 0, nil, fmt.Errorf("atxp server: client credentials for %s: %w", s.server, err)
	}
	if clientID == "" || clientSecret == "" {
		return 0, nil, fmt.Errorf("atxp server: missing client credentials for %s (register the merchant first)", s.server)
	}

	buf, err := json.Marshal(body)
	if err != nil {
		return 0, nil, fmt.Errorf("atxp server: marshal %s body: %w", path, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(buf))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", basicAuth(clientID, clientSecret))

	resp, err := s.http.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("atxp server: POST %s: %w", path, err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, respBody, nil
}

func decodeError(body []byte) (code, message string) {
	var e paymentServerError
	if err := json.Unmarshal(body, &e); err != nil {
		return "UNKNOWN_ERROR", strings.TrimSpace(string(body))
	}
	return e.describe()
}

func basicAuth(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

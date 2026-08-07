// Command mcppay-client pays for an MCP tool call whose payment challenge
// arrives inline in the CallToolResult, rather than as an HTTP 402. Some MCP
// servers gate a tool this way: an unauthenticated call returns a
// {status:"payment_required", challenge:{x402:{...}}} result instead of a
// transport-level 402, and expect the signed credential back as a tool
// argument on retry. That's the MCP-tool-shaped counterpart to
// examples/x402stranger's HTTP-402 client; this one drives x402signer the
// same way, just against a different transport for the challenge/retry.
//
// Usage:
//
//	MCP_ENDPOINT=http://127.0.0.1:8080/mcp \
//	MCP_API_KEY=<bearer token> \
//	X402_PRIVATE_KEY=<hex> \
//	go run ./examples/mcppay/client \
//	    -tool account -arg action=buy_credits -arg pack=Starter
//
// Pass -challenge-only to stop after the first call and print the
// payment_required result, without ever loading a key, signing, or paying —
// useful for proving a merchant's challenge path (e.g. DCR registration)
// works without moving any money:
//
//	MCP_ENDPOINT=http://127.0.0.1:8080/mcp MCP_API_KEY=<bearer token> \
//	go run ./examples/mcppay/client -challenge-only \
//	    -tool account -arg action=buy_credits -arg pack=Starter
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	atxp "github.com/justinstimatze/chit"
	"github.com/justinstimatze/chit/x402signer"
)

// challengeEnvelope is the payment_required shape this example expects back
// from the first call: {status, message, challenge:{x402:{...}}}. Only the
// fields needed to sign are decoded; the rest of the challenge
// (paymentRequestId, mpp, etc.) is opaque here and passed through nowhere,
// since this account only speaks x402.
type challengeEnvelope struct {
	Status    string `json:"status"`
	Message   string `json:"message"`
	Challenge struct {
		X402 json.RawMessage `json:"x402"`
	} `json:"challenge"`
}

func main() {
	toolName := flag.String("tool", "account", "MCP tool name to call")
	credArg := flag.String("credential-arg", "payment_credential", "argument name the retry call carries the signed credential under")
	network := flag.String("network", "eip155:8453", "CAIP-2 network to pin the signature to (empty accepts any offered eip155 network)")
	challengeOnly := flag.Bool("challenge-only", false, "stop after the first call and print the payment_required challenge; never signs or pays")
	var argsFlag argList
	flag.Var(&argsFlag, "arg", "tool argument as key=value (repeatable)")
	flag.Parse()

	endpoint := os.Getenv("MCP_ENDPOINT")
	if endpoint == "" {
		log.Fatal("MCP_ENDPOINT not set")
	}
	apiKey := os.Getenv("MCP_API_KEY")
	if apiKey == "" {
		log.Fatal("MCP_API_KEY not set")
	}

	var signer *x402signer.X402SignerAccount
	if !*challengeOnly {
		privHex := os.Getenv("X402_PRIVATE_KEY")
		if privHex == "" {
			log.Fatal("X402_PRIVATE_KEY not set")
		}
		var err error
		signer, err = x402signer.NewFromPrivateKeyHex(privHex, *network)
		if err != nil {
			log.Fatalf("x402signer: %v", err)
		}
		log.Printf("paying as %s", signer.Address())
	}

	ctx := context.Background()
	client := mcp.NewClient(&mcp.Implementation{Name: "mcppay-client", Version: "v0.1.0"}, nil)
	transport := &mcp.StreamableClientTransport{
		Endpoint:   endpoint,
		HTTPClient: &http.Client{Transport: &bearerTransport{token: apiKey}},
	}
	sess, err := client.Connect(ctx, transport, nil)
	if err != nil {
		log.Fatalf("Connect: %v", err)
	}
	defer func() { _ = sess.Close() }()

	args := argsFlag.toMap()

	text, err := callTool(ctx, sess, *toolName, args)
	if err != nil {
		log.Fatalf("initial call: %v", err)
	}
	log.Printf("initial result: %s", text)

	var env challengeEnvelope
	if err := json.Unmarshal([]byte(text), &env); err != nil || env.Status != "payment_required" {
		log.Fatalf("expected a payment_required result, got: %s", text)
	}
	if len(env.Challenge.X402) == 0 {
		log.Fatal("payment_required result carried no challenge.x402")
	}
	if *challengeOnly {
		fmt.Println(text)
		return
	}

	result, err := signer.Authorize(ctx, atxp.AuthorizeParams{PaymentRequirements: env.Challenge.X402})
	if err != nil {
		log.Fatalf("Authorize: %v", err)
	}
	log.Printf("signed x402 credential (protocol=%s)", result.Protocol)

	args[*credArg] = result.Credential
	text, err = callTool(ctx, sess, *toolName, args)
	if err != nil {
		log.Fatalf("settle call: %v", err)
	}
	fmt.Println(text)
}

func callTool(ctx context.Context, sess *mcp.ClientSession, name string, args map[string]any) (string, error) {
	res, err := sess.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		return "", err
	}
	var sb strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			sb.WriteString(tc.Text)
		}
	}
	if res.IsError {
		return "", fmt.Errorf("tool error: %s", sb.String())
	}
	return sb.String(), nil
}

// bearerTransport injects a static Bearer token, for MCP servers (like
// gemot's) that authenticate over a plain API key rather than ATXP OAuth.
type bearerTransport struct {
	token string
	base  http.RoundTripper
}

func (t *bearerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header.Set("Authorization", "Bearer "+t.token)
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(req)
}

// argList collects repeated -arg key=value flags into a map.
type argList []string

func (a *argList) String() string { return strings.Join(*a, ",") }

func (a *argList) Set(v string) error {
	*a = append(*a, v)
	return nil
}

func (a *argList) toMap() map[string]any {
	m := make(map[string]any, len(*a))
	for _, kv := range *a {
		if k, v, ok := strings.Cut(kv, "="); ok {
			m[k] = v
		}
	}
	return m
}

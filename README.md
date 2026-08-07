# chit

**Unofficial Go client and merchant library for [ATXP](https://docs.atxp.ai).**
chit is not affiliated with, authorized by, or endorsed by Circuit & Chisel, the
makers of ATXP. For the official, supported SDK, use their TypeScript one:
https://github.com/atxp-dev/sdk

chit lets a Go program act as an ATXP **client** (pay for MCP tools), a
**merchant** (charge callers for MCP tools), or both. It includes self-custodial
x402 payments, so a payer needs no ATXP account at all.

The module path is a codename (`chit`), but the package is `atxp`, so it reads
naturally:

### Client

```go
import (
    "github.com/justinstimatze/chit"
    "github.com/modelcontextprotocol/go-sdk/mcp"
)

c, _ := atxp.New(atxp.Config{ConnectionString: os.Getenv("ATXP_CONNECTION")})
sess, _ := c.Connect(ctx, "https://search.mcp.atxp.ai/")
defer sess.Close()
res, _ := sess.CallTool(ctx, &mcp.CallToolParams{
    Name:      "search_search",
    Arguments: map[string]any{"query": "..."},
})
```

### Merchant

This example charges callers with self-custodial x402: the payer needs no
ATXP account at all. It's the minimal shape. See `examples/x402stranger` for
the complete version, including the `X402PaymentRequirements` cache a settle
call needs (omitted here for brevity):

```go
import (
    "encoding/json"
    "net/http"

    "github.com/justinstimatze/chit/server"
)

m, _ := server.New(server.Config{
    Destination:     server.StaticDestination{ID: "base:0xYourPayoutAddress"},
    ConnectionToken: connectionToken, // the merchant's own ATXP connection token
    PayeeName:       "my merchant",
})
price, _ := server.ParseAmount("0.01")

http.HandleFunc("/pay", func(w http.ResponseWriter, r *http.Request) {
    pr := server.PaymentRequest{Price: price, User: "base:0xYourPayoutAddress", Resource: resourceURL}
    if detected := server.DetectProtocol(r.Header); detected != nil {
        pr.Session = m.OpenPaymentSession(*detected, server.SettlementContext{})
    }
    ch, err := m.RequirePayment(r.Context(), pr)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    if ch != nil { // payment required: emit the challenge as a 402
        w.WriteHeader(http.StatusPaymentRequired)
        json.NewEncoder(w).Encode(ch.Data)
        return
    }
    if pr.Session != nil {
        m.CloseSession(r.Context(), pr.Session) // settles for real
    }
    w.Write([]byte("paid"))
})
```

### Paying an OAuth-gated resource with no ATXP account

The merchant above accepts a bare 402; no OAuth needed. If the resource
gates behind an OAuth 401 first, the payer needs some ATXP identity to
complete the handshake, even though the payment itself stays self-custodial.
`atxp.HybridAccount` splits the two: OAuth identity from a real
`ATXPAccount`, payment signing from `x402signer`:

```go
import (
    "github.com/justinstimatze/chit"
    "github.com/justinstimatze/chit/x402signer"
)

oauthAcct, _ := atxp.NewATXPAccount(os.Getenv("ATXP_CONNECTION"), nil)
signerAcct, _ := x402signer.NewFromPrivateKeyHex(os.Getenv("X402_PRIVATE_KEY"), "eip155:8453")

acct := &atxp.HybridAccount{Identity: oauthAcct, Payments: signerAcct}
c, _ := atxp.NewWithAccount(atxp.Config{}, acct)
```

The hosted-account client path does **no on-chain crypto**. Signing and
settlement are delegated to ATXP over HTTP. A connection string is a
**wallet-grade secret**: never log it, pass it as a CLI argument, or send it
anywhere. `x402signer/` is the exception. It signs EIP-3009 authorizations
directly with a raw secp256k1 key, isolated to its own subpackage so the root
package's dependency graph stays crypto-free.

## Status

- **Client**: done, validated end-to-end against production (discovery,
  dynamic client registration, OAuth, `/sign`, `/authorize/auto`, payment
  retry, a real paid tool call). Lives at the module root (`package atxp`).
- **Server / merchant**: done. `server.RequirePayment` gates a metered call.
  `CheckToken`/`CheckRequest` authenticate callers. `Verify`/`Settle` finalize
  a push-payment retry credential. `Merchant.OpenPaymentSession`/
  `CloseSession` let several calls sharing one retry credential settle once.
- **Self-custodial x402 signing** (`x402signer/`): done, live-verified. It
  pays an x402 "exact"-scheme challenge by signing an EIP-3009
  `transferWithAuthorization` with a raw key. No ATXP account, no OAuth, and
  no prior relationship with the merchant required. Real settlement is
  confirmed on Base mainnet and verified against the chain's own `Transfer`
  event log, not just an API response. `atxp.HybridAccount` pairs this with
  an `ATXPAccount`'s OAuth identity for resources gated behind an OAuth 401
  rather than a bare 402.

See `docs/PROTOCOL.md`'s payment-modes table for exactly which combinations
of payer identity, destination, and resource gate actually settle real money,
with sequence diagrams for each.

## Examples

- `examples/paidmcp`: an OAuth-gated MCP server that charges $0.01 per tool
  call, plus a client that pays it. Demonstrates the hosted-account and
  hybrid x402 paths.
- `examples/x402stranger`: a bare-402 merchant and a client with no ATXP
  account at all. Demonstrates stranger-to-stranger payment.

## Testing

```
go build ./...
go test ./...                                        # unit, no network
go test -tags atxplive -run TestLive ./...            # client live; needs funded ATXP_CONNECTION
go test -tags serverlive -run TestLive ./server/...   # merchant live; needs funded ATXP_CONNECTION
```

The live tests need a funded ATXP account connection string, read from
`ATXP_CONNECTION` or `~/.atxp/config`. A freshly `agent register`-ed account
is unfunded and fraud-blocked. Use a funded account's connection string from
the dashboard **Servers** page instead. See `docs/PROTOCOL.md` for the full
account-model details.

## Docs

- `docs/PROTOCOL.md`: the ATXP wire protocol as reverse-engineered from the
  TS SDK. Covers the OAuth and payment flow, the endpoint table, and every
  payment mode that's actually been tested live, with sequence diagrams.

## License

MIT. This is a port of Circuit & Chisel's MIT-licensed TypeScript SDK; their
copyright notice is retained in `LICENSE`. Contact: justin@justinstimatze.com

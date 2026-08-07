package server

// Wire constants ported verbatim from the reference TypeScript SDK. These define
// the on-chain identities and the payment-required signaling; a transcription
// error here would point real money at the wrong contract or address, so they
// are kept byte-for-byte and covered by a table test.

// Default ATXP authorization server. Ported from @atxp/common types.ts
// (DEFAULT_AUTHORIZATION_SERVER).
const defaultAuthorizationServer = "https://auth.atxp.ai"

// Payment-required signaling. Ported from @atxp/common paymentRequiredError.ts.
//
// paymentRequiredErrorCode is the legacy ATXP code (-30402); the SDK keeps using
// it (not the newer MPP code -32042) so that old clients still recognize the
// challenge. omniPaymentErrorCode is accepted on the client side too.
const (
	paymentRequiredErrorCode = -30402
	omniPaymentErrorCode     = -32042
	paymentRequiredPreamble  = "Payment via ATXP is required. "
)

// USDCAddresses maps a network identifier (human-readable name and CAIP-2 form)
// to the USDC contract / mint address on that network.
//
// Ported verbatim from @atxp/common constants.ts (USDC_ADDRESSES).
// Source: https://developers.circle.com/stablecoins/usdc-on-main-networks
var USDCAddresses = map[string]string{
	"base":          "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
	"base_sepolia":  "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
	"eip155:8453":   "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
	"eip155:84532":  "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
	"solana":        "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
	"solana_devnet": "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
	"solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
	"solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1": "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
}

// CAIP2Networks maps a human-readable network name to its CAIP-2 identifier,
// for the chains the CDP facilitator supports.
//
// Ported verbatim from @atxp/common constants.ts (CAIP2_NETWORKS).
// Source: https://docs.cdp.coinbase.com/x402/network-support
var CAIP2Networks = map[string]string{
	"base":          "eip155:8453",
	"base_sepolia":  "eip155:84532",
	"solana":        "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
	"solana_devnet": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
}

// solanaFeePayers maps a Solana network to the CDP facilitator's fee-payer
// address used in the x402 `extra.feePayer` field.
//
// Ported verbatim from omniChallenge.ts (SOLANA_FEE_PAYERS).
// Source: https://docs.cdp.coinbase.com/x402/network-support
var solanaFeePayers = map[string]string{
	"solana":        "BFK9TLC3edb13K6v4YyH3DwPb5DSUpkWvb7XnqCL9b4F",
	"solana_devnet": "Hc3sdEAsCGQcpgfivywog9uwtk8gUBUZgsxdME1EJy88",
}

// x402 network classification. Ported from omniChallenge.ts
// (X402_EVM_NETWORKS / X402_SVM_NETWORKS).
var (
	x402EVMNetworks = map[string]bool{"base": true, "base_sepolia": true}
	x402SVMNetworks = map[string]bool{"solana": true, "solana_devnet": true}
)

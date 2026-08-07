package server

import "context"

// Destination is where the merchant receives payment. It maps to the @atxp/common
// PaymentDestination interface (only the two methods the merchant side needs).
//
// AccountID returns a fully-qualified "network:address" id (e.g.
// "atxp:<uuid>" for a hosted account, or "base:0x..." for a chain account).
// Sources returns the per-chain receive addresses used to build x402 and MPP
// challenge options; returning an empty slice is fine — the challenge then
// advertises only the ATXP-native rail, which is always included.
type Destination interface {
	AccountID(ctx context.Context) (string, error)
	Sources(ctx context.Context, include []string) ([]Source, error)
}

// StaticDestination is a Destination with a fixed account id and address set.
// Suitable for a merchant that knows its receive addresses up front.
type StaticDestination struct {
	ID        string   // "network:address"
	Addresses []Source // per-chain receive addresses (may be empty)
}

func (d StaticDestination) AccountID(context.Context) (string, error) { return d.ID, nil }

func (d StaticDestination) Sources(context.Context, []string) ([]Source, error) {
	return d.Addresses, nil
}

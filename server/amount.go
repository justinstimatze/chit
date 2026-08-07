package server

import (
	"fmt"
	"math/big"
	"regexp"
	"strings"
)

// decimalRe constrains a USDC amount to a plain non-negative decimal. It rejects
// the exotic forms big.Rat would otherwise accept — hex ("0x10"), scientific
// ("1e3"), signs, fractions ("1/3") — none of which a money string should carry.
var decimalRe = regexp.MustCompile(`^[0-9]+(\.[0-9]+)?$`)

// stablecoinDecimals is the number of decimal places for USDC and pathUSD.
// Ported verbatim from omniChallenge.ts (STABLECOIN_DECIMALS).
const stablecoinDecimals = 6

// microScale is 10^stablecoinDecimals — the factor between a human-readable USDC
// amount and its on-chain micro-unit integer.
var microScale = new(big.Int).Exp(big.NewInt(10), big.NewInt(stablecoinDecimals), nil)

// Amount is a non-negative USDC money value held as an exact integer count of
// micro-units (6 decimals). Money is never represented as a float: every amount
// that crosses the wire — the chargeAmount string, the x402 integer amount, the
// MPP amounts — is derived from this exact representation.
//
// The TS SDK uses BigNumber for the same role; Amount is the Go equivalent
// constrained to the one currency chit settles (USDC/pathUSD, both 6-decimal).
type Amount struct {
	micros *big.Int // count of 10^-6 USDC units; always >= 0
}

// ParseAmount parses a decimal USDC string (e.g. "0.01", "1", "0.000001") into
// an exact Amount. It rejects negatives, blanks, non-numeric input, and any
// value with more than 6 decimal places (which cannot be represented on-chain).
//
// Rejecting rather than rounding is deliberate: silently truncating a sub-micro
// fraction would let a caller request a price the merchant cannot actually charge.
func ParseAmount(s string) (Amount, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Amount{}, fmt.Errorf("amount: empty string")
	}
	if !decimalRe.MatchString(s) {
		return Amount{}, fmt.Errorf("amount: %q is not a plain non-negative decimal", s)
	}
	// big.Rat then parses the validated decimal exactly.
	r, ok := new(big.Rat).SetString(s)
	if !ok {
		return Amount{}, fmt.Errorf("amount: %q is not a valid decimal", s)
	}
	// Scale by 10^6 and require an integer result (no sub-micro remainder).
	scaled := new(big.Rat).Mul(r, new(big.Rat).SetInt(microScale))
	if !scaled.IsInt() {
		return Amount{}, fmt.Errorf("amount: %q has more than %d decimal places", s, stablecoinDecimals)
	}
	return Amount{micros: new(big.Int).Set(scaled.Num())}, nil
}

// AmountFromMicros builds an Amount directly from a micro-unit count. A negative
// count is clamped to zero rather than producing an invalid (negative) Amount.
func AmountFromMicros(micros int64) Amount {
	if micros < 0 {
		micros = 0
	}
	return Amount{micros: big.NewInt(micros)}
}

// AmountFromMicroString parses an atomic micro-unit integer string (e.g. the
// x402/Solana-MPP on-chain amount, "10000") into an Amount. Unlike ParseAmount
// (which takes a human-readable decimal), this expects no decimal point.
func AmountFromMicroString(s string) (Amount, error) {
	s = strings.TrimSpace(s)
	i, ok := new(big.Int).SetString(s, 10)
	if !ok || i.Sign() < 0 {
		return Amount{}, fmt.Errorf("amount: %q is not a valid non-negative integer micro-unit count", s)
	}
	return Amount{micros: i}, nil
}

// value returns the underlying micro count, treating the zero Amount{} (nil
// micros) as 0 so an uninitialized Amount is usable.
func (a Amount) value() *big.Int {
	if a.micros == nil {
		return big.NewInt(0)
	}
	return a.micros
}

// IsZero reports whether the amount is exactly zero.
func (a Amount) IsZero() bool { return a.value().Sign() == 0 }

// IsPositive reports whether the amount is strictly greater than zero.
func (a Amount) IsPositive() bool { return a.value().Sign() > 0 }

// GreaterThan reports whether a > b.
func (a Amount) GreaterThan(b Amount) bool { return a.value().Cmp(b.value()) > 0 }

// Max returns whichever of a, b is larger.
func Max(a, b Amount) Amount {
	if a.GreaterThan(b) {
		return a
	}
	return b
}

// Min returns whichever of a, b is smaller.
func Min(a, b Amount) Amount {
	if a.GreaterThan(b) {
		return b
	}
	return a
}

// Add returns a + b.
func (a Amount) Add(b Amount) Amount {
	return Amount{micros: new(big.Int).Add(a.value(), b.value())}
}

// MicroString renders the amount as its integer micro-unit count, e.g.
// 0.01 USDC -> "10000". This is the x402 / Solana-MPP on-chain amount
// (BigNumber.times(1e6).toFixed(0) in the TS SDK).
func (a Amount) MicroString() string { return a.value().String() }

// String renders the amount as a minimal decimal USDC string, e.g. "0.01",
// "0.1", "1" — matching BigNumber.toString() so the chargeAmount embedded in a
// challenge is byte-identical to what the reference SDK would emit.
func (a Amount) String() string {
	micros := a.value()
	q, r := new(big.Int).QuoRem(micros, microScale, new(big.Int))
	if r.Sign() == 0 {
		return q.String()
	}
	// Zero-pad the fractional part to 6 digits, then trim trailing zeros.
	frac := fmt.Sprintf("%0*d", stablecoinDecimals, r)
	frac = strings.TrimRight(frac, "0")
	return q.String() + "." + frac
}

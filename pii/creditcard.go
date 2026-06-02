package pii

import (
	"regexp"

	"github.com/mattevans/obscura"
)

// creditCardRegex matches 13–19 digit sequences, optionally grouped in fours by spaces or
// hyphens. The Luhn filter (declared in DefaultFilters) rejects sequences that are not valid
// card numbers, so the regex can afford to be liberal.
var creditCardRegex = regexp.MustCompile(`\b(?:\d[ \-]?){12,18}\d\b`)

// CreditCard detects payment card numbers, validated downstream by the Luhn checksum.
type CreditCard struct{}

// NewCreditCard returns a payment-card detector.
func NewCreditCard() obscura.Detector { return CreditCard{} }

// Name identifies the detector.
func (CreditCard) Name() string { return "pii:credit-card" }

// Detect returns candidate card numbers found in text, keeping only those that pass the Luhn
// checksum so non-cards never reach the resolver.
func (CreditCard) Detect(text string) []obscura.Match {
	all := findMatches(creditCardRegex, text, obscura.KindCreditCard, 0.7, "pii:credit-card")

	kept := all[:0]
	for _, m := range all {
		if validLuhn(m.Value) {
			kept = append(kept, m)
		}
	}

	return kept
}

// DefaultFilters asks the Scrubber to use nearby cue words (e.g. "card", "visa") to lift
// confidence. Luhn validation happens during detection, so no checksum filter is required here.
func (CreditCard) DefaultFilters() []obscura.Filter {
	return []obscura.Filter{obscura.NewContextKeywordFilter(32, false)}
}

var _ obscura.Detector = CreditCard{}

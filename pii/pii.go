// Package pii provides pure-Go, regex-based detectors for structured personally identifiable
// information: email addresses, phone numbers, payment cards, bank identifiers, network
// addresses, government IDs, and cryptocurrency addresses.
//
// Each detector implements obscura.Detector and may declare the validation filters it expects
// (e.g. the credit-card detector asks for a Luhn check) via DefaultFilters. Register them with
// obscura.WithDetectors(pii.All()...).
package pii

import (
	"regexp"

	"github.com/mattevans/obscura"
)

// All returns one instance of every built-in PII detector, ready to register with a Scrubber.
// Options (e.g. WithLocales) are forwarded to the locale-aware detectors — phone, bank, gov-ID,
// and business-ID — and ignored by the rest. With no options every supported jurisdiction is
// recognised.
func All(opts ...Option) []obscura.Detector {
	return []obscura.Detector{
		NewEmail(),
		NewPhone(opts...),
		NewCreditCard(),
		NewBank(opts...),
		NewNetwork(),
		NewGovID(opts...),
		NewBusinessID(opts...),
		NewCrypto(),
	}
}

// findMatches runs re over text and returns one Match per non-overlapping hit, tagged with the
// given kind, score, and rule id. Byte offsets come straight from the regexp engine.
func findMatches(re *regexp.Regexp, text string, kind obscura.Kind, score float64, rule string) []obscura.Match {
	locs := re.FindAllStringIndex(text, -1)
	if len(locs) == 0 {
		return nil
	}
	out := make([]obscura.Match, 0, len(locs))
	for _, loc := range locs {
		out = append(out, obscura.Match{
			Kind:  kind,
			Start: loc[0],
			End:   loc[1],
			Value: text[loc[0]:loc[1]],
			Score: score,
			Rule:  rule,
		})
	}
	return out
}

package pii

import (
	"github.com/mattevans/obscura"
)

// Bank detects bank routing and account identifiers: the jurisdiction-agnostic IBAN, plus
// domestic routing codes — US ABA routing number, UK sort code, AU BSB, and NZ bank account.
// The rules live in the per-locale files (locale_*.go); WithLocales selects which domestic codes
// are active, while IBAN (which carries its own country code) is always recognised.
type Bank struct {
	rules []localeRule
}

// NewBank returns a bank-identifier detector. With no options every supported jurisdiction is
// recognised; pass WithLocales to narrow the domestic codes.
func NewBank(opts ...Option) obscura.Detector {
	rules := rulesForKinds(obscura.KindIBAN, obscura.KindRouting)
	return Bank{rules: selectRules(rules, newLocaleConfig(opts))}
}

// Name identifies the detector.
func (Bank) Name() string { return "pii:bank" }

// Detect returns candidate bank identifiers. Checksummed kinds (IBAN, ABA) are validated during
// detection; unchecksummed domestic codes (sort code, BSB, NZ account) are gated on a nearby cue.
func (b Bank) Detect(text string) []obscura.Match {
	return detectRules(b.rules, text)
}

var _ obscura.Detector = Bank{}

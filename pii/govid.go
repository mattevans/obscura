package pii

import (
	"github.com/mattevans/obscura"
)

// GovID detects government-issued identity numbers across jurisdictions: US SSN, UK NINO,
// AU TFN, and NZ IRD. The rules themselves live in the per-locale files (locale_*.go); which
// jurisdictions are active is controlled by WithLocales.
type GovID struct {
	rules []localeRule
}

// NewGovID returns a government-ID detector. With no options every supported jurisdiction is
// recognised; pass WithLocales to narrow it.
func NewGovID(opts ...Option) obscura.Detector {
	return GovID{rules: selectRules(rulesForKinds(obscura.KindGovID), newLocaleConfig(opts))}
}

// Name identifies the detector.
func (GovID) Name() string { return "pii:gov-id" }

// Detect returns candidate government IDs found in text, each validated and cue-gated per its
// jurisdiction's rule.
func (g GovID) Detect(text string) []obscura.Match {
	return detectRules(g.rules, text)
}

// DefaultFilters uses nearby cue words (e.g. "ssn", "tax file") to lift confidence on these
// otherwise ambiguous numeric identifiers. Checksum validation (AU TFN, NZ IRD) and cue-gating
// happen during detection, so no checksum filter is required here.
func (GovID) DefaultFilters() []obscura.Filter {
	return []obscura.Filter{obscura.NewContextKeywordFilter(40, false)}
}

var _ obscura.Detector = GovID{}

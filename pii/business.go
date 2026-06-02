package pii

import (
	"github.com/mattevans/obscura"
)

// BusinessID detects public business-register identifiers across jurisdictions: the Australian
// Business Number (ABN) and the New Zealand Business Number (NZBN). Unlike a government identity
// number these are not secret — they sit in public registers — but a privacy-sensitive gateway
// may still redact them, and their checksums make detection reliable. The rules live in the
// per-locale files (locale_*.go); WithLocales selects which jurisdictions are active.
type BusinessID struct {
	rules []localeRule
}

// NewBusinessID returns a business-identifier detector. With no options every supported
// jurisdiction is recognised; pass WithLocales to narrow it.
func NewBusinessID(opts ...Option) obscura.Detector {
	return BusinessID{rules: selectRules(rulesForKinds(obscura.KindBusinessID), newLocaleConfig(opts))}
}

// Name identifies the detector.
func (BusinessID) Name() string { return "pii:business-id" }

// Detect returns candidate ABNs and NZBNs found in text, each validated by its checksum during
// detection so non-identifiers never reach the resolver.
func (b BusinessID) Detect(text string) []obscura.Match {
	return detectRules(b.rules, text)
}

var _ obscura.Detector = BusinessID{}

package pii

import (
	"regexp"

	"github.com/mattevans/obscura"
)

// phoneRunTrailing matches a separator-led continuation of further digit groups, used to
// recognise that a phone candidate is really a fragment clipped from a longer numeric run
// (e.g. a card or account number) on its trailing side. The group is two-to-four digits so a
// short leading group of a spaced identifier (e.g. the "11" of a 2-3-3-3 ABN) is still caught.
var phoneRunTrailing = regexp.MustCompile(`^[ .\-]\d{2,4}`)

// phoneRunLeading matches a digit group plus separator immediately before a candidate, the
// leading-side counterpart of phoneRunTrailing.
var phoneRunLeading = regexp.MustCompile(`\d{2,4}[ .\-]$`)

// Phone detects telephone numbers: the jurisdiction-agnostic E.164 and international grouped
// forms, plus per-locale national formats. The rules live in the per-locale files (locale_*.go);
// WithLocales selects which national formats are active, while the + forms are always recognised.
type Phone struct {
	rules []localeRule
}

// NewPhone returns a telephone-number detector. With no options every supported jurisdiction is
// recognised; pass WithLocales to narrow the national formats.
func NewPhone(opts ...Option) obscura.Detector {
	return Phone{rules: selectRules(rulesForKinds(obscura.KindPhone), newLocaleConfig(opts))}
}

// Name identifies the detector.
func (Phone) Name() string { return "pii:phone" }

// Detect returns every phone number found in text. Overlapping hits from the + forms and the
// national patterns are reconciled later by overlap resolution.
func (p Phone) Detect(text string) []obscura.Match {
	return detectRules(p.rules, text)
}

// DefaultFilters vetoes phone candidates that are merely a fragment clipped from a longer run of
// digit groups — for example part of a card or account number — which the deliberately loose
// grouped-phone patterns can otherwise pick up.
func (Phone) DefaultFilters() []obscura.Filter {
	return []obscura.Filter{phoneRunFilter{}}
}

var _ obscura.Detector = Phone{}

// phoneRunFilter rejects a phone match when the surrounding text continues the digit grouping on
// either side, indicating the match is a slice of a longer numeric token rather than a standalone
// phone number.
type phoneRunFilter struct{}

// Name identifies the filter for audit and debugging.
func (phoneRunFilter) Name() string { return "pii:phone-run" }

// Apply vetoes phone candidates embedded in a longer run of grouped digits.
func (phoneRunFilter) Apply(m obscura.Match, fc obscura.FilterContext) (float64, bool) {
	if m.Kind != obscura.KindPhone {
		return m.Score, true
	}
	if phoneRunTrailing.MatchString(fc.Text[m.End:]) || phoneRunLeading.MatchString(fc.Text[:m.Start]) {
		return 0, false
	}
	return m.Score, true
}

var _ obscura.Filter = phoneRunFilter{}

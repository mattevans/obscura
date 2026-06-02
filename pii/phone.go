package pii

import (
	"regexp"

	"github.com/mattevans/obscura"
)

// Phone number formats are inherently ambiguous, so we match only reasonably structured forms
// and assign a modest score, leaving the final decision to the Scrubber's threshold.
var phoneRegexes = []*regexp.Regexp{
	// E.164: a leading + and 7–15 digits.
	regexp.MustCompile(`\+\d{7,15}\b`),
	// International grouped form: a + country code, then an area code (which may be a single
	// digit) and two subscriber groups, e.g. +44 20 7946 0958, +61 2 8014 1234.
	regexp.MustCompile(`\+\d{1,3}[ .\-]\d{1,4}[ .\-]\d{3,4}[ .\-]\d{3,4}\b`),
	// National grouped form: an area code of two to four digits (optionally parenthesised) and
	// two subscriber groups, e.g. (02) 9374 4000, 415-555-0132. Requiring a two-digit-plus area
	// code keeps four-group identifiers such as a malformed 11-digit ABN from matching in full;
	// any leftover three-group fragment is rejected by phoneRunFilter.
	regexp.MustCompile(`\b\(?\d{2,4}\)?[ .\-]\d{3,4}[ .\-]\d{3,4}\b`),
}

// phoneRunContinues matches a separator-led continuation of further digit groups, used to
// recognise that a phone candidate is really a fragment clipped from a longer numeric run
// (e.g. a card or account number) on its trailing side.
var phoneRunTrailing = regexp.MustCompile(`^[ .\-]\d{3,4}`)

// phoneRunLeading matches a digit group plus separator immediately before a candidate, the
// leading-side counterpart of phoneRunTrailing.
var phoneRunLeading = regexp.MustCompile(`\d{3,4}[ .\-]$`)

// Phone detects telephone numbers in E.164 and common grouped formats.
type Phone struct{}

// NewPhone returns a telephone-number detector.
func NewPhone() obscura.Detector { return Phone{} }

// Name identifies the detector.
func (Phone) Name() string { return "pii:phone" }

// Detect returns every phone number found in text, deduplicating overlapping hits from the
// different format patterns.
func (Phone) Detect(text string) []obscura.Match {
	var matches []obscura.Match
	for _, re := range phoneRegexes {
		matches = append(matches, findMatches(re, text, obscura.KindPhone, 0.6, "pii:phone")...)
	}
	return matches
}

// DefaultFilters vetoes phone candidates that are merely a fragment clipped from a longer run
// of digit groups — for example part of a card or account number — which the deliberately loose
// grouped-phone pattern can otherwise pick up.
func (Phone) DefaultFilters() []obscura.Filter {
	return []obscura.Filter{phoneRunFilter{}}
}

var _ obscura.Detector = Phone{}

// phoneRunFilter rejects a phone match when the surrounding text continues the digit grouping
// on either side, indicating the match is a slice of a longer numeric token rather than a
// standalone phone number.
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

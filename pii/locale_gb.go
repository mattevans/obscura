package pii

import (
	"regexp"

	"github.com/mattevans/obscura"
)

var (
	// ninoRegex matches UK National Insurance numbers (two prefix letters, six digits, a suffix
	// letter), allowing an optional space grouping.
	ninoRegex = regexp.MustCompile(`\b[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z] ?\d{2} ?\d{2} ?\d{2} ?[A-D]\b`)
	// sortCodeRegex matches a UK sort code (three hyphen-separated digit pairs). It carries no
	// checksum, so the rule is cue-gated.
	sortCodeRegex = regexp.MustCompile(`\b\d{2}-\d{2}-\d{2}\b`)
	// gbPhoneRegex matches a UK national number: a leading-zero trunk code and two subscriber
	// groups, e.g. 020 7946 0958, 0161 496 0000.
	gbPhoneRegex = regexp.MustCompile(`\b0\d{2,4} \d{3,4} \d{3,4}\b`)
)

// gbRules returns the identifier rules for the United Kingdom: NINO (gov-ID), the cue-gated sort
// code (routing), and the national phone format.
func gbRules() []localeRule {
	return []localeRule{
		{locale: LocaleGB, kind: obscura.KindGovID, rule: "pii:nino", re: ninoRegex, score: 0.7},
		{
			locale: LocaleGB, kind: obscura.KindRouting, rule: "pii:sort-code", re: sortCodeRegex, score: 0.6,
			requireCue: true, cues: []string{"sort code", "sort-code", "sortcode"},
		},
		{locale: LocaleGB, kind: obscura.KindPhone, rule: "pii:phone", re: gbPhoneRegex, score: 0.6},
	}
}

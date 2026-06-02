package pii

import (
	"regexp"

	"github.com/mattevans/obscura"
)

var (
	// tfnRegex matches Australian Tax File Numbers written as three spaced groups of three.
	tfnRegex = regexp.MustCompile(`\b\d{3} \d{3} \d{3}\b`)
	// abnRegex matches an Australian Business Number: eleven digits, either contiguous or in the
	// conventional 2-3-3-3 spaced grouping. The mod-89 checksum rejects non-ABNs.
	abnRegex = regexp.MustCompile(`\b\d{2} \d{3} \d{3} \d{3}\b|\b\d{11}\b`)
	// bsbRegex matches an Australian BSB (two hyphen-separated digit triples). It carries no
	// checksum, so the rule is cue-gated.
	bsbRegex = regexp.MustCompile(`\b\d{3}-\d{3}\b`)
	// auPhoneRegex matches an Australian landline: an (0N) area code and two four-digit groups,
	// e.g. (02) 9374 4000, 02 9374 4000.
	auPhoneRegex = regexp.MustCompile(`\b\(?0\d\)? \d{4} \d{4}\b`)
	// auMobileRegex matches an Australian mobile, e.g. 0412 345 678.
	auMobileRegex = regexp.MustCompile(`\b04\d{2} \d{3} \d{3}\b`)
)

// auRules returns the identifier rules for Australia: TFN (gov-ID), ABN (business-ID), the
// cue-gated BSB (routing), and the landline and mobile phone formats.
func auRules() []localeRule {
	const phoneScore = 0.6

	return []localeRule{
		{locale: LocaleAU, kind: obscura.KindGovID, rule: "pii:tfn", re: tfnRegex, score: 0.55, validate: validTFN},
		{locale: LocaleAU, kind: obscura.KindBusinessID, rule: "pii:abn", re: abnRegex, score: 0.6, validate: validABN},
		{
			locale: LocaleAU, kind: obscura.KindRouting, rule: "pii:bsb", re: bsbRegex, score: 0.6,
			requireCue: true, cues: []string{"bsb"},
		},
		{locale: LocaleAU, kind: obscura.KindPhone, rule: rulePhone, re: auPhoneRegex, score: phoneScore},
		{locale: LocaleAU, kind: obscura.KindPhone, rule: rulePhone, re: auMobileRegex, score: phoneScore},
	}
}

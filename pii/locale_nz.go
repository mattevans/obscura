package pii

import (
	"regexp"

	"github.com/mattevans/obscura"
)

var (
	// irdRegex matches a New Zealand IRD number, either contiguous (eight or nine digits) or in the
	// conventional hyphen-grouped form. The bare-digit form is loose, so the IRD rule is both
	// checksum-validated and cue-gated.
	irdRegex = regexp.MustCompile(`\b\d{2,3}-\d{3}-\d{3}\b|\b\d{8,9}\b`)
	// nzbnRegex matches a New Zealand Business Number: thirteen contiguous digits (a GS1 GLN).
	// The EAN-13 check digit rejects non-NZBNs.
	nzbnRegex = regexp.MustCompile(`\b\d{13}\b`)
	// nzAccountRegex matches a New Zealand bank account number (bank-branch-account-suffix). The
	// shape is distinctive but unchecksummed here, so the rule is cue-gated.
	nzAccountRegex = regexp.MustCompile(`\b\d{2}-\d{4}-\d{7}-\d{2,3}\b`)
	// nzPhoneRegex matches a New Zealand landline: an (0N) area code and two subscriber groups,
	// e.g. (09) 123 4567, 03 123 4567.
	nzPhoneRegex = regexp.MustCompile(`\b\(?0\d\)? \d{3,4} \d{4}\b`)
	// nzMobileRegex matches a New Zealand mobile, e.g. 021 234 5678, 027 123 456.
	nzMobileRegex = regexp.MustCompile(`\b02\d \d{3} \d{3,4}\b`)
)

// nzRules returns the identifier rules for New Zealand: IRD (gov-ID), NZBN (business-ID), the
// cue-gated bank account (routing), and the landline and mobile phone formats.
func nzRules() []localeRule {
	const phoneScore = 0.6

	return []localeRule{
		{
			locale: LocaleNZ, kind: obscura.KindGovID, rule: "pii:ird", re: irdRegex, score: 0.6,
			validate: validIRD, requireCue: true, cues: []string{"ird", "inland revenue"},
		},
		{locale: LocaleNZ, kind: obscura.KindBusinessID, rule: "pii:nzbn", re: nzbnRegex, score: 0.6, validate: validNZBN},
		{
			locale: LocaleNZ, kind: obscura.KindRouting, rule: "pii:nz-bank-account", re: nzAccountRegex, score: 0.6,
			requireCue: true, cues: []string{"bank", "account", "a/c"},
		},
		{locale: LocaleNZ, kind: obscura.KindPhone, rule: rulePhone, re: nzPhoneRegex, score: phoneScore},
		{locale: LocaleNZ, kind: obscura.KindPhone, rule: rulePhone, re: nzMobileRegex, score: phoneScore},
	}
}

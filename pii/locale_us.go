package pii

import (
	"regexp"

	"github.com/mattevans/obscura"
)

var (
	// ssnRegex matches US Social Security Numbers in the canonical dashed form.
	ssnRegex = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
	// abaRegex matches any nine-digit run; the ABA weighted checksum rejects non-routing numbers,
	// which removes the vast majority of false positives.
	abaRegex = regexp.MustCompile(`\b\d{9}\b`)
	// usPhoneRegex matches the North American grouped form: a three-digit area code (optionally
	// parenthesised) and 3-4 subscriber digits, e.g. (415) 555-0132, 212-555-0188.
	usPhoneRegex = regexp.MustCompile(`\b\(?\d{3}\)?[ .\-]\d{3}[ .\-]\d{4}\b`)
)

// usRules returns the identifier rules for the United States: SSN (gov-ID), ABA routing number,
// and the North American grouped phone format.
func usRules() []localeRule {
	return []localeRule{
		{locale: LocaleUS, kind: obscura.KindGovID, rule: "pii:ssn", re: ssnRegex, score: 0.7},
		{locale: LocaleUS, kind: obscura.KindRouting, rule: "pii:aba", re: abaRegex, score: 0.55, validate: validABA},
		{locale: LocaleUS, kind: obscura.KindPhone, rule: rulePhone, re: usPhoneRegex, score: 0.6},
	}
}

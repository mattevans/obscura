package pii

import (
	"regexp"

	"github.com/mattevans/obscura"
)

var (
	// ibanRegex matches the structural shape of an IBAN: two-letter country code, two check
	// digits, then up to 30 alphanumerics. The mod-97 checksum validates it. An IBAN carries its
	// own country code, so it is jurisdiction-agnostic and always active.
	ibanRegex = regexp.MustCompile(`\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b`)
	// e164Regex matches an E.164 number: a leading + and 7–15 digits. It carries its own country
	// code, so it is jurisdiction-agnostic and always active.
	e164Regex = regexp.MustCompile(`\+\d{7,15}\b`)
	// intlGroupedRegex matches an international grouped form: a + country code, an area code (which
	// may be a single digit), and two subscriber groups, e.g. +44 20 7946 0958, +61 2 8014 1234.
	// It too is jurisdiction-agnostic.
	intlGroupedRegex = regexp.MustCompile(`\+\d{1,3}[ .\-]\d{1,4}[ .\-]\d{3,4}[ .\-]\d{3,4}\b`)
)

// localeAnyRules returns the jurisdiction-agnostic identifier rules: formats that carry their own
// country code (IBAN, E.164, and the international grouped phone form) and so stay active no matter
// which locales WithLocales selects.
func localeAnyRules() []localeRule {
	const phoneScore = 0.6

	return []localeRule{
		{locale: localeAny, kind: obscura.KindIBAN, rule: "pii:iban", re: ibanRegex, score: 0.8, validate: validIBAN},
		{locale: localeAny, kind: obscura.KindPhone, rule: rulePhone, re: e164Regex, score: phoneScore},
		{locale: localeAny, kind: obscura.KindPhone, rule: rulePhone, re: intlGroupedRegex, score: phoneScore},
	}
}

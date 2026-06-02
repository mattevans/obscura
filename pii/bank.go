package pii

import (
	"regexp"

	"github.com/mattevans/obscura"
)

var (
	// ibanRegex matches the structural shape of an IBAN: two-letter country code, two check
	// digits, then up to 30 alphanumerics. The mod-97 checksum filter validates it.
	ibanRegex = regexp.MustCompile(`\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b`)
	// abaRegex matches any nine-digit run; the ABA weighted checksum filter rejects non-routing
	// numbers, which removes the vast majority of false positives.
	abaRegex = regexp.MustCompile(`\b\d{9}\b`)
)

// Bank detects bank account identifiers: IBANs and US ABA routing numbers.
type Bank struct{}

// NewBank returns a bank-identifier detector.
func NewBank() obscura.Detector { return Bank{} }

// Name identifies the detector.
func (Bank) Name() string { return "pii:bank" }

// Detect returns candidate IBANs and ABA routing numbers found in text.
func (Bank) Detect(text string) []obscura.Match {
	matches := findMatches(ibanRegex, text, obscura.KindIBAN, 0.8, "pii:iban")
	matches = append(matches, findMatches(abaRegex, text, obscura.KindRouting, 0.55, "pii:aba")...)
	return matches
}

// DefaultFilters asks the Scrubber to validate IBAN mod-97 and ABA weighted checksums.
func (Bank) DefaultFilters() []obscura.Filter {
	return []obscura.Filter{obscura.NewChecksumFilter()}
}

var _ obscura.Detector = Bank{}

package pii

import (
	"regexp"

	"github.com/mattevans/obscura"
)

var (
	// ssnRegex matches US Social Security Numbers in the canonical dashed form.
	ssnRegex = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
	// ninoRegex matches UK National Insurance numbers (two prefix letters, six digits, a suffix
	// letter), allowing an optional space grouping.
	ninoRegex = regexp.MustCompile(`\b[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z] ?\d{2} ?\d{2} ?\d{2} ?[A-D]\b`)
	// tfnRegex matches Australian Tax File Numbers written as three spaced groups of three.
	tfnRegex = regexp.MustCompile(`\b\d{3} \d{3} \d{3}\b`)
)

// GovID detects government-issued identity numbers: US SSN, UK NINO, and AU TFN.
type GovID struct{}

// NewGovID returns a government-ID detector.
func NewGovID() obscura.Detector { return GovID{} }

// Name identifies the detector.
func (GovID) Name() string { return "pii:gov-id" }

// Detect returns candidate government IDs found in text.
func (GovID) Detect(text string) []obscura.Match {
	matches := findMatches(ssnRegex, text, obscura.KindGovID, 0.7, "pii:ssn")
	matches = append(matches, findMatches(ninoRegex, text, obscura.KindGovID, 0.7, "pii:nino")...)
	matches = append(matches, findMatches(tfnRegex, text, obscura.KindGovID, 0.55, "pii:tfn")...)
	return matches
}

// DefaultFilters uses nearby cue words (e.g. "ssn", "tax file") to lift confidence on these
// otherwise ambiguous numeric identifiers, and validates the Australian TFN checksum so a
// genuine TFN is confirmed rather than left looking like a loosely-matched phone number.
func (GovID) DefaultFilters() []obscura.Filter {
	return []obscura.Filter{
		obscura.NewContextKeywordFilter(40, false),
		obscura.NewChecksumFilter(),
	}
}

var _ obscura.Detector = GovID{}

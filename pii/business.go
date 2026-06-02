package pii

import (
	"regexp"

	"github.com/mattevans/obscura"
)

var (
	// abnRegex matches an Australian Business Number: eleven digits, either contiguous or in the
	// conventional 2-3-3-3 spaced grouping. The mod-89 checksum filter rejects non-ABNs.
	abnRegex = regexp.MustCompile(`\b\d{2} \d{3} \d{3} \d{3}\b|\b\d{11}\b`)
	// nzbnRegex matches a New Zealand Business Number: thirteen contiguous digits (a GS1 GLN).
	// The EAN-13 check-digit filter rejects non-NZBNs.
	nzbnRegex = regexp.MustCompile(`\b\d{13}\b`)
)

// BusinessID detects public business-register identifiers: the Australian Business Number (ABN)
// and the New Zealand Business Number (NZBN). Unlike a government identity number (SSN, TFN)
// these are not secret — they are looked up in public registers — but a privacy-sensitive
// gateway may still wish to redact them, and their checksums make detection reliable.
type BusinessID struct{}

// NewBusinessID returns a business-identifier detector.
func NewBusinessID() obscura.Detector { return BusinessID{} }

// Name identifies the detector.
func (BusinessID) Name() string { return "pii:business-id" }

// Detect returns candidate ABNs and NZBNs found in text, validated downstream by their
// checksums.
func (BusinessID) Detect(text string) []obscura.Match {
	matches := findMatches(abnRegex, text, obscura.KindBusinessID, 0.6, "pii:abn")
	matches = append(matches, findMatches(nzbnRegex, text, obscura.KindBusinessID, 0.6, "pii:nzbn")...)
	return matches
}

// DefaultFilters validates the ABN mod-89 and NZBN EAN-13 checksums, which removes essentially
// all false positives from the otherwise liberal digit-run patterns.
func (BusinessID) DefaultFilters() []obscura.Filter {
	return []obscura.Filter{obscura.NewChecksumFilter()}
}

var _ obscura.Detector = BusinessID{}

package pii

import (
	"regexp"

	"github.com/mattevans/obscura"
)

var (
	// ethRegex matches Ethereum-style 20-byte hex addresses.
	ethRegex = regexp.MustCompile(`\b0x[a-fA-F0-9]{40}\b`)
	// btcRegex matches legacy base58 (P2PKH/P2SH) and bech32 (bc1) Bitcoin addresses.
	btcRegex = regexp.MustCompile(`\b(?:bc1[02-9ac-hj-np-z]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b`)
)

// Crypto detects cryptocurrency addresses (Bitcoin and Ethereum).
type Crypto struct{}

// NewCrypto returns a cryptocurrency-address detector.
func NewCrypto() obscura.Detector { return Crypto{} }

// Name identifies the detector.
func (Crypto) Name() string { return "pii:crypto" }

// Detect returns candidate crypto addresses found in text.
func (Crypto) Detect(text string) []obscura.Match {
	matches := findMatches(ethRegex, text, obscura.KindCrypto, 0.85, "pii:eth")
	matches = append(matches, findMatches(btcRegex, text, obscura.KindCrypto, 0.8, "pii:btc")...)
	return matches
}

var _ obscura.Detector = Crypto{}

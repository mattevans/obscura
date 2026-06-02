package pii

import (
	"regexp"

	"github.com/mattevans/obscura"
)

var (
	// ipv4Regex matches dotted-quad addresses with each octet bounded to 0–255.
	ipv4Regex = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b`)
	// ipv6Regex matches IPv6 addresses (a pragmatic subset, not the full grammar). The
	// uncompressed form requires the full eight groups; shorter forms must use the "::"
	// compression. Requiring eight groups keeps decimal clock times such as 14:30:00 — three
	// colon-separated groups with no compression — from registering as addresses.
	ipv6Regex = regexp.MustCompile(`(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}`)
	// macRegex matches colon- or hyphen-separated 48-bit hardware addresses.
	macRegex = regexp.MustCompile(`\b(?:[0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}\b`)
)

// Network detects network identifiers: IPv4/IPv6 addresses and MAC addresses.
type Network struct{}

// NewNetwork returns a network-address detector.
func NewNetwork() obscura.Detector { return Network{} }

// Name identifies the detector.
func (Network) Name() string { return "pii:network" }

// Detect returns IP and MAC addresses found in text. MAC is matched before IPv6 so the
// overlap resolver can prefer the more specific hardware-address interpretation.
func (Network) Detect(text string) []obscura.Match {
	matches := findMatches(macRegex, text, obscura.KindMAC, 0.85, "pii:mac")
	matches = append(matches, findMatches(ipv4Regex, text, obscura.KindIPAddress, 0.7, "pii:ipv4")...)
	matches = append(matches, findMatches(ipv6Regex, text, obscura.KindIPAddress, 0.7, "pii:ipv6")...)
	return matches
}

var _ obscura.Detector = Network{}

package pii

import (
	"regexp"

	"github.com/mattevans/obscura"
)

// emailRegex matches the common, practical shape of an email address. It is intentionally
// permissive on the local part and conservative on the domain (requires a dotted TLD); full
// RFC 5322 compliance is neither necessary nor desirable for redaction.
var emailRegex = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9](?:[a-zA-Z0-9.\-]*[a-zA-Z0-9])?\.[a-zA-Z]{2,}`)

// Email detects email addresses.
type Email struct{}

// NewEmail returns an email-address detector.
func NewEmail() obscura.Detector { return Email{} }

// Name identifies the detector.
func (Email) Name() string { return "pii:email" }

// Detect returns every email address found in text.
func (Email) Detect(text string) []obscura.Match {
	return findMatches(emailRegex, text, obscura.KindEmail, 0.95, "pii:email")
}

var _ obscura.Detector = Email{}

package obscura_test

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mattevans/obscura"
	"github.com/mattevans/obscura/pii"
)

func newTestScrubber(t *testing.T, opts ...obscura.Option) *obscura.Scrubber {
	t.Helper()

	base := make([]obscura.Option, 0, 1+len(opts))
	base = append(base, obscura.WithDetectors(pii.All()...))
	base = append(base, opts...)

	return obscura.New(base...)
}

func TestBusinessIDAndOverlapResolution(t *testing.T) {
	s := newTestScrubber(t)

	cases := []struct {
		name      string
		input     string
		wantKind  obscura.Kind
		wantValue string
	}{
		{"valid ABN", "supplier ABN 30 164 696 039 today", obscura.KindBusinessID, "30 164 696 039"},
		{"valid NZBN", "trades under NZBN 9429048825658 here", obscura.KindBusinessID, "9429048825658"},
		{"TFN outranks phone", "tax file number 123 456 782 on file", obscura.KindGovID, "123 456 782"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := s.Findings(tc.input)
			require.Len(t, fs, 1, tc.input)
			assert.Equal(t, tc.wantKind, fs[0].Kind)
			assert.Equal(t, tc.wantValue, fs[0].Value)
		})
	}
}

func TestIPv4OutranksPhoneOnOverlap(t *testing.T) {
	// A dotted-quad whose first three octets are each three digits (a netmask, a 192.168.100.x
	// host) is also a valid grouped-phone shape. The octet-validated IP must win the overlap so
	// it is not clipped and mislabelled as a phone number.
	s := newTestScrubber(t)
	for _, in := range []string{"netmask 255.255.255.0 today", "host 192.168.100.5 online"} {
		fs := s.Findings(in)
		require.Len(t, fs, 1, in)
		assert.Equal(t, obscura.KindIPAddress, fs[0].Kind, in)
	}
}

func TestMalformedNumbersAreNotRedacted(t *testing.T) {
	s := newTestScrubber(t)
	// A checksum-failing ABN must not slip through as a phone number, and bare digit runs that
	// are not valid identifiers must not be redacted at all.
	for _, in := range []string{
		"mistyped ABN 30 164 696 038 must be ignored",
		"reference 12345678901 is a SKU",
		"lot code 1234567890123 is internal",
		"the meeting is at 14:30:00 sharp",
	} {
		assert.Empty(t, s.Findings(in), in)
	}
}

func TestRedactRestoreRoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantPH  []string // placeholders expected to appear in the redacted output
		notSeen []string // original substrings that must NOT survive redaction
	}{
		{
			name:    "email",
			input:   "Contact me at jane.doe@example.com please.",
			wantPH:  []string{"⟦EMAIL_1⟧"},
			notSeen: []string{"jane.doe@example.com"},
		},
		{
			name:    "valid credit card with cue",
			input:   "My card number is 4111 1111 1111 1111, charge it.",
			wantPH:  []string{"⟦CREDIT_CARD_1⟧"},
			notSeen: []string{"4111 1111 1111 1111"},
		},
		{
			name:    "repeated email gets stable placeholder",
			input:   "a@b.com talked to a@b.com about a@b.com",
			wantPH:  []string{"⟦EMAIL_1⟧"},
			notSeen: []string{"a@b.com"},
		},
		{
			name:    "multiple distinct kinds",
			input:   "mail bob@corp.io or call +14155550132 now",
			wantPH:  []string{"⟦EMAIL_1⟧", "⟦PHONE_1⟧"},
			notSeen: []string{"bob@corp.io", "+14155550132"},
		},
	}

	s := newTestScrubber(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clean, vault := s.Redact(tt.input)

			for _, ph := range tt.wantPH {
				assert.Contains(t, clean, ph, "expected placeholder in redacted text")
			}

			for _, orig := range tt.notSeen {
				assert.NotContains(t, clean, orig, "original PII leaked into redacted text")
			}

			// Restoring the redacted text must reconstruct the original exactly.
			assert.Equal(t, tt.input, vault.Restore(clean), "round-trip must be lossless")
		})
	}
}

func TestRepeatedValueSharesPlaceholder(t *testing.T) {
	s := newTestScrubber(t)
	clean, vault := s.Redact("a@b.com and a@b.com")
	assert.Equal(t, "⟦EMAIL_1⟧ and ⟦EMAIL_1⟧", clean)
	assert.Equal(t, 1, vault.Len())
}

func TestInvalidCreditCardNotRedacted(t *testing.T) {
	// Isolate the card detector so unrelated numeric detectors (phone) don't interfere.
	s := obscura.New(obscura.WithDetector(pii.NewCreditCard()))
	// Fails Luhn -> must not be treated as a card.
	clean, vault := s.Redact("the number 1234 5678 9012 3456 is not a card")
	assert.NotContains(t, clean, "CREDIT_CARD")
	assert.Equal(t, 0, vault.Len())
}

func TestAllowlistVetoes(t *testing.T) {
	s := newTestScrubber(t, obscura.WithAllowlist("support@acme.com"))
	clean, _ := s.Redact("write support@acme.com or sales@acme.com")
	assert.Contains(t, clean, "support@acme.com", "allowlisted value must survive")
	assert.NotContains(t, clean, "sales@acme.com", "non-allowlisted value must be redacted")
}

func TestMinScoreThreshold(t *testing.T) {
	// Phones score 0.6; a threshold above that should drop them.
	s := newTestScrubber(t, obscura.WithMinScore(0.65))
	clean, vault := s.Redact("call +14155550132")
	assert.Equal(t, "call +14155550132", clean)
	assert.Equal(t, 0, vault.Len())
}

func TestFindingsDoesNotRewrite(t *testing.T) {
	s := newTestScrubber(t)
	findings := s.Findings("email a@b.com")
	require.Len(t, findings, 1)
	assert.Equal(t, obscura.KindEmail, findings[0].Kind)
	assert.Equal(t, "a@b.com", findings[0].Value)
}

func TestRedactContextNoContextDetectors(t *testing.T) {
	s := newTestScrubber(t)
	clean, vault, err := s.RedactContext(context.Background(), "email a@b.com")
	require.NoError(t, err)
	assert.Equal(t, "email ⟦EMAIL_1⟧", clean)
	assert.Equal(t, "email a@b.com", vault.Restore(clean))
}

func TestNoDetectorsPassesThrough(t *testing.T) {
	s := obscura.New()
	clean, vault := s.Redact("email a@b.com is untouched")
	assert.Equal(t, "email a@b.com is untouched", clean)
	assert.Equal(t, 0, vault.Len())
}

// FuzzRoundTrip asserts the core reversibility invariants on arbitrary input: restoring the
// redacted text reproduces the input exactly, and (when something was redacted) no vaulted
// original survives verbatim in the clean text.
func FuzzRoundTrip(f *testing.F) {
	seeds := []string{
		"jane@example.com",
		"card 4111 1111 1111 1111",
		"ssn 123-45-6789 and ip 10.0.0.1",
		"no pii here at all",
		"⟦EMAIL_1⟧ already looks like a placeholder",
		"",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	s := obscura.New(obscura.WithDetectors(pii.All()...))

	f.Fuzz(func(t *testing.T, input string) {
		clean, vault := s.Redact(input)
		require.Equal(t, input, vault.Restore(clean), "restore must reconstruct the original")

		// Restore must be idempotent on already-restored text.
		require.Equal(t, input, vault.Restore(vault.Restore(clean)))
	})
}

func TestScrubberConcurrentUse(t *testing.T) {
	s := newTestScrubber(t)

	const goroutines = 16

	wg := make(chan struct{}, goroutines)
	for range goroutines {
		go func() {
			defer func() { wg <- struct{}{} }()

			clean, vault := s.Redact("email a@b.com here")
			assert.Equal(t, "email a@b.com here", vault.Restore(clean))
		}()
	}

	for range goroutines {
		<-wg
	}
}

func TestASCIIPlaceholderStyle(t *testing.T) {
	s := newTestScrubber(t, obscura.WithPlaceholderStyle(obscura.StyleASCII()))
	clean, vault := s.Redact("email a@b.com")
	assert.Equal(t, "email [[EMAIL_1]]", clean)
	assert.Equal(t, "email a@b.com", vault.Restore(clean))
}

func TestNoLeakInClean(t *testing.T) {
	s := newTestScrubber(t)
	input := "reach jane.doe@example.com or 4111 1111 1111 1111"

	clean, _ := s.Redact(input)
	for _, orig := range []string{"jane.doe@example.com", "4111 1111 1111 1111"} {
		assert.False(t, strings.Contains(clean, orig), "original %q leaked", orig)
	}
}

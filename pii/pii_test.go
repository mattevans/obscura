package pii_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mattevans/obscura"
	"github.com/mattevans/obscura/pii"
)

// detect runs a single detector and returns its matches, applying no filters.
func detect(d obscura.Detector, text string) []obscura.Match {
	return d.Detect(text)
}

func TestEmailDetect(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{"jane.doe@example.com", []string{"jane.doe@example.com"}},
		{"a+tag@sub.example.co.uk here", []string{"a+tag@sub.example.co.uk"}},
		{"two a@b.com and c@d.org", []string{"a@b.com", "c@d.org"}},
		{"no email here", nil},
		{"not@an", nil},
	}

	d := pii.NewEmail()
	for _, tt := range tests {
		got := valuesOf(detect(d, tt.in))
		assert.Equal(t, tt.want, got, tt.in)
	}
}

func TestCreditCardDetectAndLuhn(t *testing.T) {
	d := pii.NewCreditCard()
	// The Luhn check runs during detection: a valid card surfaces, a Luhn-invalid run does not.
	got := detect(d, "pay 4111 1111 1111 1111 now")
	require.Len(t, got, 1)
	assert.Equal(t, obscura.KindCreditCard, got[0].Kind)
	assert.Empty(t, detect(d, "ref 1234 5678 9012 3456 only"), "Luhn-invalid run is not a card")

	// The detector still declares a cue-word filter to lift confidence.
	fp, ok := d.(interface{ DefaultFilters() []obscura.Filter })
	require.True(t, ok)
	require.NotEmpty(t, fp.DefaultFilters())
}

func TestBankIBAN(t *testing.T) {
	d := pii.NewBank()
	// A structurally valid IBAN (GB checksum correct).
	got := detect(d, "send to GB82WEST12345698765432 please")

	var found bool

	for _, m := range got {
		if m.Kind == obscura.KindIBAN {
			found = true
		}
	}

	assert.True(t, found, "expected an IBAN candidate")
}

func TestNetworkIPv4(t *testing.T) {
	d := pii.NewNetwork()
	got := valuesOf(detect(d, "server at 192.168.1.1 and 256.1.1.1 invalid"))
	assert.Contains(t, got, "192.168.1.1")
	assert.NotContains(t, got, "256.1.1.1")
}

func TestNetworkMAC(t *testing.T) {
	d := pii.NewNetwork()
	got := valuesOf(detect(d, "mac 00:1A:2B:3C:4D:5E here"))
	assert.Contains(t, got, "00:1A:2B:3C:4D:5E")
}

func TestNetworkIPv6(t *testing.T) {
	d := pii.NewNetwork()
	// A full eight-group address is matched; a decimal clock time is not.
	got := valuesOf(detect(d, "endpoint 2001:0db8:85a3:0000:0000:8a2e:0370:7334 at 14:30:00"))
	assert.Contains(t, got, "2001:0db8:85a3:0000:0000:8a2e:0370:7334")
	assert.NotContains(t, got, "14:30:00")
}

func TestPhoneInternationalSingleDigitArea(t *testing.T) {
	d := pii.NewPhone()
	got := valuesOf(detect(d, "fax +61 2 8014 1234 please"))
	assert.Contains(t, got, "+61 2 8014 1234")
}

func TestBusinessIDDetect(t *testing.T) {
	d := pii.NewBusinessID()
	// Checksums run during detection, so a valid ABN and NZBN surface while a checksum-failing
	// 11-digit run does not.
	got := valuesOf(detect(d, "abn 30 164 696 039 and nzbn 9429048825658"))
	assert.Contains(t, got, "30 164 696 039")
	assert.Contains(t, got, "9429048825658")
	assert.Empty(t, detect(d, "ref 12345678901 is a SKU"), "checksum-failing run is not a business ID")
}

func TestGovIDSSN(t *testing.T) {
	d := pii.NewGovID()
	got := valuesOf(detect(d, "ssn 123-45-6789"))
	assert.Contains(t, got, "123-45-6789")
}

func TestCryptoETH(t *testing.T) {
	d := pii.NewCrypto()
	addr := "0x52908400098527886E0F7030069857D2E4169EE7"
	got := valuesOf(detect(d, "send to "+addr))
	assert.Contains(t, got, addr)
}

func TestAllReturnsEveryDetector(t *testing.T) {
	got := pii.All()
	assert.Len(t, got, 8)

	names := make(map[string]bool, len(got))
	for _, d := range got {
		names[d.Name()] = true
	}

	for _, want := range []string{"pii:email", "pii:phone", "pii:credit-card", "pii:bank", "pii:network", "pii:gov-id", "pii:business-id", "pii:crypto"} {
		assert.True(t, names[want], "missing detector %s", want)
	}
}

func valuesOf(matches []obscura.Match) []string {
	if len(matches) == 0 {
		return nil
	}

	out := make([]string, 0, len(matches))
	for _, m := range matches {
		out = append(out, m.Value)
	}

	return out
}

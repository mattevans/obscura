package obscura

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTFNChecksum(t *testing.T) {
	assert.True(t, tfnValid("123 456 782"), "valid TFN")
	assert.False(t, tfnValid("123 456 781"), "wrong check digit")
	assert.True(t, isTFNShaped("123 456 782"))
	assert.False(t, isTFNShaped("123-45-6789"), "SSN is not TFN-shaped")
	assert.False(t, isTFNShaped("AB123456C"), "NINO is not TFN-shaped")
}

func TestABNChecksum(t *testing.T) {
	assert.True(t, businessIDValid("30 164 696 039"), "valid spaced ABN")
	assert.True(t, businessIDValid("51824753556"), "valid unspaced ABN")
	assert.False(t, businessIDValid("30 164 696 038"), "wrong ABN checksum")
	assert.False(t, businessIDValid("12345678901"), "random 11 digits")
}

func TestNZBNChecksum(t *testing.T) {
	assert.True(t, businessIDValid("9429048825658"), "valid NZBN")
	assert.False(t, businessIDValid("9429048825650"), "wrong NZBN check digit")
	assert.False(t, businessIDValid("1234567890123"), "random 13 digits")
	assert.False(t, businessIDValid("123456789"), "wrong length")
}

func TestChecksumFilterByKind(t *testing.T) {
	f := checksumFilter{}

	// A government-ID that is not TFN-shaped (an SSN) passes untouched — it carries no checksum.
	_, keep := f.Apply(Match{Kind: KindGovID, Value: "123-45-6789", Score: 0.7}, FilterContext{})
	assert.True(t, keep, "SSN should not be vetoed by the TFN checksum")

	// A TFN-shaped gov-ID with a bad checksum is vetoed.
	_, keep = f.Apply(Match{Kind: KindGovID, Value: "123 456 781", Score: 0.7}, FilterContext{})
	assert.False(t, keep, "invalid TFN should be vetoed")

	// A business ID with a bad checksum is vetoed; a valid one survives.
	_, keep = f.Apply(Match{Kind: KindBusinessID, Value: "30 164 696 038", Score: 0.6}, FilterContext{})
	assert.False(t, keep, "invalid ABN should be vetoed")
	_, keep = f.Apply(Match{Kind: KindBusinessID, Value: "9429048825658", Score: 0.6}, FilterContext{})
	assert.True(t, keep, "valid NZBN should survive")
}

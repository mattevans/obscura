package pii

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidLuhn(t *testing.T) {
	assert.True(t, validLuhn("4111 1111 1111 1111"), "valid Visa test number")
	assert.False(t, validLuhn("1234 5678 9012 3456"), "fails Luhn")
	assert.False(t, validLuhn(""), "empty has no digits")
}

func TestValidIBAN(t *testing.T) {
	assert.True(t, validIBAN("GB82WEST12345698765432"), "valid GB IBAN")
	assert.True(t, validIBAN("DE89370400440532013000"), "valid DE IBAN")
	assert.False(t, validIBAN("GB00WEST12345698765432"), "wrong check digits")
}

func TestValidABA(t *testing.T) {
	assert.True(t, validABA("021000021"), "valid routing number")
	assert.False(t, validABA("123456789"), "fails ABA mod-10")
	assert.False(t, validABA("02100002"), "wrong length")
}

func TestValidTFN(t *testing.T) {
	assert.True(t, validTFN("123 456 782"), "valid spaced TFN")
	assert.False(t, validTFN("123 456 781"), "wrong check digit")
	assert.False(t, validTFN("12345678"), "wrong length")
}

func TestValidABN(t *testing.T) {
	assert.True(t, validABN("30 164 696 039"), "valid spaced ABN")
	assert.True(t, validABN("51824753556"), "valid unspaced ABN")
	assert.False(t, validABN("30 164 696 038"), "wrong ABN checksum")
	assert.False(t, validABN("12345678901"), "random 11 digits")
}

func TestValidNZBN(t *testing.T) {
	assert.True(t, validNZBN("9429048825658"), "valid NZBN")
	assert.False(t, validNZBN("9429048825650"), "wrong NZBN check digit")
	assert.False(t, validNZBN("123456789"), "wrong length")
}

func TestValidIRD(t *testing.T) {
	// Valid IRD numbers: 49091850 resolves on the primary weights; 49098576 and the nine-digit
	// 136410132 fall through to the secondary weights.
	for _, ird := range []string{"49091850", "35901981", "49098576", "136410132", "49-098-576"} {
		assert.Truef(t, validIRD(ird), "%s should be a valid IRD", ird)
	}
	// Wrong check digit, out of range, and wrong length are all rejected.
	for _, ird := range []string{"49091851", "136410131", "9999999", "150000001"} {
		assert.Falsef(t, validIRD(ird), "%s should be rejected", ird)
	}
}

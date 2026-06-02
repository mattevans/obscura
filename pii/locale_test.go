package pii_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/mattevans/obscura"
	"github.com/mattevans/obscura/pii"
)

func TestGovIDLocaleGating(t *testing.T) {
	// The default recognises every jurisdiction.
	all := pii.NewGovID()
	assert.NotEmpty(t, detect(all, "ssn 123-45-6789"), "US SSN")
	assert.NotEmpty(t, detect(all, "tfn 123 456 782"), "AU TFN")
	assert.NotEmpty(t, detect(all, "ird 49091850"), "NZ IRD")

	// Narrowing to the US keeps SSN but drops the AU and NZ identifiers.
	us := pii.NewGovID(pii.WithLocales(pii.LocaleUS))
	assert.NotEmpty(t, detect(us, "ssn 123-45-6789"), "US SSN still matches")
	assert.Empty(t, detect(us, "tfn 123 456 782"), "AU TFN gated out")
	assert.Empty(t, detect(us, "ird 49091850"), "NZ IRD gated out")
}

func TestIRDRequiresCue(t *testing.T) {
	d := pii.NewGovID(pii.WithLocales(pii.LocaleNZ))
	assert.NotEmpty(t, detect(d, "their ird number is 49091850 on file"), "cue present")
	assert.Empty(t, detect(d, "order 49091850 shipped today"), "no cue, bare 8-digit run is not redacted")
	assert.Empty(t, detect(d, "ird 49091851 is mistyped"), "checksum failure is rejected even with a cue")
}

func TestBankLocaleGatingAndCues(t *testing.T) {
	// IBAN is jurisdiction-agnostic: present even when locales are narrowed to AU.
	au := pii.NewBank(pii.WithLocales(pii.LocaleAU))
	assert.NotEmpty(t, detect(au, "wire to GB82WEST12345698765432 today"), "IBAN always active")
	assert.NotEmpty(t, detect(au, "the bsb 123-456 for the branch"), "AU BSB with cue")
	assert.Empty(t, detect(au, "routing 021000021 here"), "US ABA gated out under AU-only")

	// UK sort code and NZ account need their cue; bare codes are not redacted.
	gb := pii.NewBank(pii.WithLocales(pii.LocaleGB))
	assert.NotEmpty(t, detect(gb, "sort code 09-01-28 for transfers"), "UK sort code with cue")
	assert.Empty(t, detect(gb, "the score was 09-01-28 last night"), "no cue, not a sort code")

	nz := pii.NewBank(pii.WithLocales(pii.LocaleNZ))
	got := valuesOf(detect(nz, "pay into account 12-3456-1234567-12 please"))
	assert.Contains(t, got, "12-3456-1234567-12", "NZ bank account with cue")
}

func TestABAStillChecksummedNoCue(t *testing.T) {
	// A US routing number is checksum-validated and needs no cue word.
	d := pii.NewBank(pii.WithLocales(pii.LocaleUS))
	assert.NotEmpty(t, detect(d, "021000021"), "valid ABA, no cue required")
	assert.Empty(t, detect(d, "123456789"), "ABA checksum failure rejected")
}

func TestPhoneLocaleGating(t *testing.T) {
	// E.164 and the international grouped form are always active.
	us := pii.NewPhone(pii.WithLocales(pii.LocaleUS))
	assert.NotEmpty(t, detect(us, "call +14155550199 now"), "E.164 always active")
	assert.NotEmpty(t, detect(us, "fax +61 2 8014 1234 please"), "intl grouped always active")
	assert.NotEmpty(t, detect(us, "ring 415-555-0132 today"), "US national active")
	assert.Empty(t, detect(us, "desk (02) 9374 4000 here"), "AU national gated out under US-only")

	au := pii.NewPhone(pii.WithLocales(pii.LocaleAU))
	got := valuesOf(detect(au, "mobile 0412 345 678 for delivery"))
	assert.Contains(t, got, "0412 345 678", "AU mobile active under AU")
}

func TestWithLocalesAppliesToAll(t *testing.T) {
	ds := pii.All(pii.WithLocales(pii.LocaleUS))
	assert.Len(t, ds, 8, "All still returns every detector")

	s := obscura.New(obscura.WithDetectors(ds...))
	// A US SSN is redacted; an AU TFN passes through untouched under a US-only configuration.
	clean, _ := s.Redact("ssn 123-45-6789 and tfn 123 456 782")
	assert.Contains(t, clean, "GOV_ID", "US SSN redacted")
	assert.Contains(t, clean, "123 456 782", "AU TFN left intact under US-only locales")
}

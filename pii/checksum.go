package pii

import "strings"

// This file holds the checksum validators for structured PII identifiers. They live in the pii
// package (rather than the root) because each locale rule in locale.go names the validator it
// trusts, and detection vetoes a candidate inline the moment its checksum fails — so an invalid
// identifier never enters the overlap resolver in the first place.

// digitsOnly returns the decimal digits of s, dropping spaces, hyphens, and other separators.
func digitsOnly(s string) []int {
	out := make([]int, 0, len(s))
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= '0' && c <= '9' {
			out = append(out, int(c-'0'))
		}
	}
	return out
}

// validLuhn reports whether the digits in s satisfy the Luhn checksum. Non-digit bytes (spaces,
// dashes) are ignored, and at least one digit must be present.
func validLuhn(s string) bool {
	sum := 0
	alt := false
	count := 0
	for i := len(s) - 1; i >= 0; i-- {
		c := s[i]
		if c < '0' || c > '9' {
			continue
		}
		d := int(c - '0')
		count++
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return count > 0 && sum%10 == 0
}

// validIBAN reports whether s is a structurally valid IBAN per the mod-97 check (ISO 13616).
func validIBAN(s string) bool {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' || c == '-' {
			continue
		}
		b.WriteByte(c)
	}
	iban := strings.ToUpper(b.String())
	if len(iban) < 15 || len(iban) > 34 {
		return false
	}
	// Move the first four characters to the end, then convert letters to numbers (A=10..Z=35).
	rearranged := iban[4:] + iban[:4]
	var digits strings.Builder
	digits.Grow(len(rearranged) * 2)
	for i := 0; i < len(rearranged); i++ {
		c := rearranged[i]
		switch {
		case c >= '0' && c <= '9':
			digits.WriteByte(c)
		case c >= 'A' && c <= 'Z':
			digits.WriteString(itoaByte(int(c-'A') + 10))
		default:
			return false
		}
	}
	return mod97(digits.String()) == 1
}

// validABA reports whether s is a valid 9-digit ABA routing number (weighted mod-10).
func validABA(s string) bool {
	d := digitsOnly(s)
	if len(d) != 9 {
		return false
	}
	sum := 3*(d[0]+d[3]+d[6]) + 7*(d[1]+d[4]+d[7]) + (d[2] + d[5] + d[8])
	return sum%10 == 0
}

// validTFN reports whether s holds nine digits satisfying the Australian Tax File Number weighted
// mod-11 checksum.
func validTFN(s string) bool {
	d := digitsOnly(s)
	if len(d) != 9 {
		return false
	}
	weights := [9]int{1, 4, 3, 7, 5, 8, 6, 9, 10}
	sum := 0
	for i := range 9 {
		sum += d[i] * weights[i]
	}
	return sum%11 == 0
}

// validABN reports whether s holds eleven digits satisfying the Australian Business Number
// checksum: subtract one from the leading digit, apply the positional weights, and require the
// weighted sum to be divisible by 89.
func validABN(s string) bool {
	d := digitsOnly(s)
	if len(d) != 11 {
		return false
	}
	weights := [11]int{10, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19}
	sum := (d[0] - 1) * weights[0]
	for i := 1; i < 11; i++ {
		sum += d[i] * weights[i]
	}
	return sum%89 == 0
}

// validNZBN reports whether s holds thirteen digits satisfying the EAN-13 (GS1 GLN) check digit
// used by the New Zealand Business Number: the first twelve digits weighted alternately by one
// and three must, with the check digit, sum to a multiple of ten.
func validNZBN(s string) bool {
	d := digitsOnly(s)
	if len(d) != 13 {
		return false
	}
	sum := 0
	for i := range 12 {
		if i%2 == 0 {
			sum += d[i]
		} else {
			sum += d[i] * 3
		}
	}
	check := (10 - sum%10) % 10
	return check == d[12]
}

// validIRD reports whether s holds a valid New Zealand IRD number. An IRD number is eight or nine
// digits in the range 10,000,000–150,000,000; the final digit is a mod-11 check digit over the
// base (left-padded to eight digits). The primary weight set is tried first, and a check digit of
// ten falls back to the secondary set — if that also yields ten the number is invalid.
func validIRD(s string) bool {
	d := digitsOnly(s)
	if len(d) < 8 || len(d) > 9 {
		return false
	}
	n := 0
	for _, x := range d {
		n = n*10 + x
	}
	if n < 10_000_000 || n > 150_000_000 {
		return false
	}
	check := d[len(d)-1]
	base := d[:len(d)-1]
	// Left-pad the base to eight digits so the weights line up regardless of an 8- or 9-digit IRD.
	var padded [8]int
	copy(padded[8-len(base):], base)

	c := irdCheckDigit(padded, [8]int{3, 2, 7, 6, 5, 4, 3, 2})
	if c == 10 {
		c = irdCheckDigit(padded, [8]int{7, 4, 3, 2, 5, 2, 7, 6})
		if c == 10 {
			return false
		}
	}
	return c == check
}

// irdCheckDigit applies one IRD weight set to the padded base and returns the resulting check
// digit (which may be ten, signalling the caller to retry with the secondary weights).
func irdCheckDigit(base [8]int, weights [8]int) int {
	sum := 0
	for i := range 8 {
		sum += base[i] * weights[i]
	}
	if r := sum % 11; r != 0 {
		return 11 - r
	}
	return 0
}

// mod97 computes a large decimal string modulo 97 without bignum, processing digit by digit.
func mod97(digits string) int {
	rem := 0
	for i := 0; i < len(digits); i++ {
		rem = (rem*10 + int(digits[i]-'0')) % 97
	}
	return rem
}

// itoaByte renders a small non-negative int (10..35) as decimal digits.
func itoaByte(n int) string {
	if n < 10 {
		return string(rune('0' + n))
	}
	return string(rune('0'+n/10)) + string(rune('0'+n%10))
}

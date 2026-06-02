package obscura

import (
	"math"
	"regexp"
	"strings"
)

// tfnShapeRegex matches the Australian TFN's three-spaced-groups-of-three form. It is anchored
// so SSNs (dashed 3-2-4) and NINOs (lettered) are not treated as TFNs and so skip the TFN
// checksum entirely.
var tfnShapeRegex = regexp.MustCompile(`^\d{3} \d{3} \d{3}$`)

// FilterContext gives a filter access to the surrounding input so it can make context-aware
// decisions (e.g. look for a cue word near a bare number).
type FilterContext struct {
	Text string // the full input being scrubbed.
}

// Filter post-processes a candidate Match, returning the (possibly adjusted) confidence score
// and whether to keep the match. A keep of false vetoes the candidate outright.
//
// Filters MUST be pure and safe for concurrent use. Each filter self-selects by Kind, so a
// filter that does not apply to a match returns the score unchanged with keep=true.
type Filter interface {
	Name() string
	Apply(m Match, fc FilterContext) (score float64, keep bool)
}

// luhnFilter vetoes credit-card candidates that fail the Luhn checksum.
type luhnFilter struct{}

// checksumFilter validates structured numeric identifiers: IBAN (mod-97) and ABA routing
// (weighted mod-10). Candidates of other kinds pass through unchanged.
type checksumFilter struct{}

// entropyFilter vetoes low-entropy secret candidates. Below minBits Shannon bits per
// character a string is too regular to be a real key.
type entropyFilter struct {
	minBits float64
}

// contextKeywordFilter lifts the score of a match when a cue word for its kind appears within
// window bytes, and optionally vetoes bare numerics that have no nearby cue at all.
type contextKeywordFilter struct {
	cues      map[Kind][]string
	window    int
	vetoNoCue bool
	appliesTo map[Kind]bool
}

// allowFilter vetoes any match whose value is on the allowlist (e.g. a public support email).
type allowFilter struct {
	values map[string]struct{}
}

// denyFilter forces any match whose value is on the denylist to maximum confidence.
type denyFilter struct {
	values map[string]struct{}
}

// minScoreFilter is the final gate: it drops any match scoring below the policy threshold.
type minScoreFilter struct {
	min float64
}

// NewLuhnFilter returns a Filter that rejects credit-card candidates failing the Luhn check.
func NewLuhnFilter() Filter { return luhnFilter{} }

// NewChecksumFilter returns a Filter validating IBAN and ABA routing checksums.
func NewChecksumFilter() Filter { return checksumFilter{} }

// NewEntropyFilter returns a Filter that vetoes secret candidates below minBits bits/char.
func NewEntropyFilter(minBits float64) Filter { return entropyFilter{minBits: minBits} }

// NewContextKeywordFilter returns a Filter that uses nearby cue words to adjust the
// confidence of numeric identifiers. With vetoNoCue, bare numerics lacking any cue are
// dropped — useful to suppress arbitrary digit runs masquerading as SSNs.
func NewContextKeywordFilter(window int, vetoNoCue bool) Filter {
	return contextKeywordFilter{
		cues:      defaultCues(),
		window:    window,
		vetoNoCue: vetoNoCue,
		appliesTo: map[Kind]bool{KindGovID: true, KindCreditCard: true},
	}
}

func newAllowFilter(values []string) Filter {
	set := make(map[string]struct{}, len(values))
	for _, v := range values {
		set[v] = struct{}{}
	}
	return allowFilter{values: set}
}

func newDenyFilter(values []string) Filter {
	set := make(map[string]struct{}, len(values))
	for _, v := range values {
		set[v] = struct{}{}
	}
	return denyFilter{values: set}
}

func newMinScoreFilter(min float64) Filter { return minScoreFilter{min: min} }

// Name identifies the filter for audit and debugging.
func (luhnFilter) Name() string { return "pii:luhn" }

// Apply rejects credit-card candidates whose digits fail the Luhn checksum.
func (luhnFilter) Apply(m Match, _ FilterContext) (float64, bool) {
	if m.Kind != KindCreditCard {
		return m.Score, true
	}
	if !luhnValid(m.Value) {
		return 0, false
	}
	return m.Score, true
}

// Name identifies the filter for audit and debugging.
func (checksumFilter) Name() string { return "pii:checksum" }

// Apply validates structured-identifier checksums, vetoing candidates that fail. IBAN uses
// mod-97 and ABA routing a weighted mod-10. A government-ID candidate shaped like an Australian
// TFN (nine digits) is validated with the TFN weighted mod-11; other gov-ID shapes (SSN, NINO)
// carry no checksum and pass through untouched.
func (checksumFilter) Apply(m Match, _ FilterContext) (float64, bool) {
	switch m.Kind {
	case KindIBAN:
		if !ibanValid(m.Value) {
			return 0, false
		}
	case KindRouting:
		if !abaValid(m.Value) {
			return 0, false
		}
	case KindGovID:
		if isTFNShaped(m.Value) && !tfnValid(m.Value) {
			return 0, false
		}
	case KindBusinessID:
		if !businessIDValid(m.Value) {
			return 0, false
		}
	}
	return m.Score, true
}

// Name identifies the filter for audit and debugging.
func (entropyFilter) Name() string { return "secret:entropy" }

// Apply vetoes secret candidates whose Shannon entropy is below the configured floor.
func (f entropyFilter) Apply(m Match, _ FilterContext) (float64, bool) {
	if m.Kind != KindSecret || f.minBits <= 0 {
		return m.Score, true
	}
	if shannonBits(m.Value) < f.minBits {
		return 0, false
	}
	return m.Score, true
}

// Name identifies the filter for audit and debugging.
func (contextKeywordFilter) Name() string { return "pii:context-keyword" }

// Apply lifts the score when a kind-specific cue word sits near the match, and optionally
// vetoes bare numerics that have no nearby cue.
func (f contextKeywordFilter) Apply(m Match, fc FilterContext) (float64, bool) {
	if !f.appliesTo[m.Kind] {
		return m.Score, true
	}
	cues := f.cues[m.Kind]
	if len(cues) == 0 {
		return m.Score, true
	}
	if f.hasCueNearby(fc.Text, m, cues) {
		return clamp01(m.Score + 0.2), true
	}
	if f.vetoNoCue {
		return 0, false
	}
	return m.Score, true
}

// Name identifies the filter for audit and debugging.
func (allowFilter) Name() string { return "policy:allowlist" }

// Apply vetoes any match whose value is explicitly allowlisted.
func (f allowFilter) Apply(m Match, _ FilterContext) (float64, bool) {
	if _, ok := f.values[m.Value]; ok {
		return 0, false
	}
	return m.Score, true
}

// Name identifies the filter for audit and debugging.
func (denyFilter) Name() string { return "policy:denylist" }

// Apply forces any denylisted value to maximum confidence so it is always redacted.
func (f denyFilter) Apply(m Match, _ FilterContext) (float64, bool) {
	if _, ok := f.values[m.Value]; ok {
		return 1, true
	}
	return m.Score, true
}

// Name identifies the filter for audit and debugging.
func (minScoreFilter) Name() string { return "policy:min-score" }

// Apply drops any match scoring below the policy threshold.
func (f minScoreFilter) Apply(m Match, _ FilterContext) (float64, bool) {
	if m.Score < f.min {
		return m.Score, false
	}
	return m.Score, true
}

// hasCueNearby reports whether any cue word appears within the filter's window around the
// match span (case-insensitive).
func (f contextKeywordFilter) hasCueNearby(text string, m Match, cues []string) bool {
	lo := max(m.Start-f.window, 0)
	hi := min(m.End+f.window, len(text))
	window := strings.ToLower(text[lo:hi])
	for _, cue := range cues {
		if strings.Contains(window, cue) {
			return true
		}
	}
	return false
}

// defaultCues maps numeric kinds to the words that, when nearby, signal the number really is
// that kind of identifier.
func defaultCues() map[Kind][]string {
	return map[Kind][]string{
		KindGovID:      {"ssn", "social security", "nino", "national insurance", "tfn", "tax file"},
		KindCreditCard: {"card", "credit", "debit", "visa", "mastercard", "amex", "cvv", "cvc"},
	}
}

// luhnValid reports whether the digits in s satisfy the Luhn checksum. Non-digit bytes
// (spaces, dashes) are ignored.
func luhnValid(s string) bool {
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

// ibanValid reports whether s is a structurally valid IBAN per the mod-97 check (ISO 13616).
func ibanValid(s string) bool {
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

// abaValid reports whether s is a valid 9-digit ABA routing number (weighted mod-10).
func abaValid(s string) bool {
	var d [9]int
	n := 0
	for i := 0; i < len(s) && n < 9; i++ {
		c := s[i]
		if c < '0' || c > '9' {
			continue
		}
		d[n] = int(c - '0')
		n++
	}
	if n != 9 {
		return false
	}
	sum := 3*(d[0]+d[3]+d[6]) + 7*(d[1]+d[4]+d[7]) + (d[2] + d[5] + d[8])
	return sum%10 == 0
}

// isTFNShaped reports whether s has the Australian Tax File Number layout. Other gov-ID shapes
// (US SSN, UK NINO) return false and pass through the TFN checksum unchanged.
func isTFNShaped(s string) bool {
	return tfnShapeRegex.MatchString(s)
}

// tfnValid reports whether the nine digits in s satisfy the Australian TFN weighted mod-11
// checksum. Non-digit bytes (spaces) are ignored.
func tfnValid(s string) bool {
	weights := [9]int{1, 4, 3, 7, 5, 8, 6, 9, 10}
	var d [9]int
	n := 0
	for i := 0; i < len(s) && n < 9; i++ {
		c := s[i]
		if c < '0' || c > '9' {
			continue
		}
		d[n] = int(c - '0')
		n++
	}
	if n != 9 {
		return false
	}
	sum := 0
	for i := range 9 {
		sum += d[i] * weights[i]
	}
	return sum%11 == 0
}

// digitsOnly returns the decimal digits of s as a slice, dropping spaces and other separators.
func digitsOnly(s string) []int {
	out := make([]int, 0, len(s))
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= '0' && c <= '9' {
			out = append(out, int(c-'0'))
		}
	}
	return out
}

// businessIDValid validates a business-register identifier by length: eleven digits are checked
// as an Australian ABN (mod-89), thirteen as a New Zealand NZBN (EAN-13 check digit). Any other
// length is rejected.
func businessIDValid(s string) bool {
	switch d := digitsOnly(s); len(d) {
	case 11:
		return abnValid(d)
	case 13:
		return nzbnValid(d)
	default:
		return false
	}
}

// abnValid reports whether eleven digits satisfy the Australian Business Number checksum:
// subtract one from the leading digit, apply the positional weights, and require the weighted
// sum to be divisible by 89.
func abnValid(d []int) bool {
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

// nzbnValid reports whether thirteen digits satisfy the EAN-13 (GS1 GLN) check digit used by the
// New Zealand Business Number: the first twelve digits weighted alternately by one and three
// must, with the check digit, sum to a multiple of ten.
func nzbnValid(d []int) bool {
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

// mod97 computes a large decimal string modulo 97 without bignum, processing in chunks.
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

// shannonBits returns the Shannon entropy of s in bits per character.
func shannonBits(s string) float64 {
	if s == "" {
		return 0
	}
	var freq [256]int
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	n := float64(len(s))
	var bits float64
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		bits -= p * math.Log2(p)
	}
	return bits
}

// clamp01 constrains x to the inclusive range [0, 1].
func clamp01(x float64) float64 {
	if x < 0 {
		return 0
	}
	if x > 1 {
		return 1
	}
	return x
}

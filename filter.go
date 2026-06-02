package obscura

import (
	"math"
	"strings"
)

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

func newMinScoreFilter(minScore float64) Filter { return minScoreFilter{min: minScore} }

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
		KindGovID: {
			"ssn", "social security", "nino", "national insurance",
			"tfn", "tax file", "ird", "inland revenue",
		},
		KindCreditCard: {"card", "credit", "debit", "visa", "mastercard", "amex", "cvv", "cvc"},
	}
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

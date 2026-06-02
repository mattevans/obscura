// Package tokenfilter provides an optional obscura.Filter that suppresses secret false
// positives using BPE token efficiency. A byte-level BPE tokenizer learns its merges from
// English, so natural language compresses efficiently (~3.5–4 characters per token) while
// random, high-entropy secrets fragment into many short tokens (~1.5–2 characters per token).
// That chars-per-token ratio separates real keys from prose where Shannon entropy alone is too
// blunt.
//
// The BPE merge data lives under this package's bpe sub-package, so callers who do not opt into
// token-efficiency filtering never compile or embed it. Wire it in with one line:
//
//	obscura.New(..., obscura.WithFilter(tokenfilter.New()))
package tokenfilter

import (
	"strings"
	"unicode/utf8"

	"github.com/mattevans/obscura"
	"github.com/mattevans/obscura/secret/tokenfilter/bpe"
)

const (
	defaultMaxCharsPerToken = 3.0
	defaultMinLen           = 12
	// confidenceBump scales how much a very fragmented (secret-like) candidate's score is lifted.
	confidenceBump = 0.3
)

// Filter vetoes secret candidates that tokenize too efficiently to be random keys, and lifts
// the confidence of those that fragment heavily. It applies only to KindSecret matches; all
// other kinds pass through unchanged.
type Filter struct {
	enc    *bpe.Encoder
	maxCPT float64
	minLen int
}

// Option configures a Filter.
type Option func(*Filter)

// New returns a token-efficiency filter. By default it treats candidates that encode to more
// than ~3.0 characters per token as natural-language false positives and ignores candidates
// shorter than 12 bytes (too short for a reliable signal).
func New(opts ...Option) *Filter {
	f := &Filter{
		enc:    bpe.New(),
		maxCPT: defaultMaxCharsPerToken,
		minLen: defaultMinLen,
	}
	for _, opt := range opts {
		opt(f)
	}

	return f
}

// WithMaxCharsPerToken sets the chars-per-token threshold above which a candidate is treated as
// natural language and vetoed. Higher values are more permissive (fewer vetoes).
func WithMaxCharsPerToken(maxCPT float64) Option {
	return func(f *Filter) { f.maxCPT = maxCPT }
}

// WithMinLen sets the minimum candidate length (in bytes) the filter will judge; shorter
// candidates pass through unchanged because the ratio is unreliable for them.
func WithMinLen(n int) Option {
	return func(f *Filter) { f.minLen = n }
}

// Name identifies the filter.
func (f *Filter) Name() string { return "secret:token-efficiency" }

// Apply vetoes secret candidates that look like prose and bumps the confidence of those that
// fragment heavily under BPE. Non-secret or too-short candidates pass through unchanged.
func (f *Filter) Apply(m obscura.Match, _ obscura.FilterContext) (float64, bool) {
	if m.Kind != obscura.KindSecret || len(m.Value) < f.minLen {
		return m.Score, true
	}
	// The chars-per-token ratio is calibrated for a single contiguous credential token. A value
	// containing whitespace is a multi-word structural marker (e.g. a "-----BEGIN RSA PRIVATE
	// KEY-----" header) that a specific rule matched on purpose, not prose masquerading as a key,
	// so the natural-language heuristic does not apply.
	if strings.ContainsAny(m.Value, " \t\r\n") {
		return m.Score, true
	}

	n := f.enc.CountTokens(m.Value)
	if n == 0 {
		return m.Score, true
	}

	cpt := float64(utf8.RuneCountInString(m.Value)) / float64(n)
	if cpt > f.maxCPT {
		return 0, false // tokenizes like natural language -> drop as a false positive
	}
	// Lower chars-per-token means more fragmented, hence more secret-like: lift the score.
	bumped := m.Score + (f.maxCPT-cpt)/f.maxCPT*confidenceBump

	return clamp01(bumped), true
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

var _ obscura.Filter = (*Filter)(nil)

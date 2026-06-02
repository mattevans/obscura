package bpe_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mattevans/obscura/secret/tokenfilter/bpe"
)

func TestCountTokensKnownValues(t *testing.T) {
	enc := bpe.New()
	// These counts treat the whole string as a single pre-token (no word-splitting regex),
	// matching how GPT-2 BPE merges a contiguous token. Common words are single tokens.
	tests := []struct {
		in   string
		want int
	}{
		{"", 0},
		{"the", 1},
		{"hello", 1},
		{" world", 1}, // leading space becomes the Ġ-prefixed single token "Ġworld"
		{"hello world", 2},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, enc.CountTokens(tt.in), "CountTokens(%q)", tt.in)
	}
}

func TestProseTokenizesMoreEfficientlyThanSecrets(t *testing.T) {
	enc := bpe.New()

	prose := "the quick brown fox jumps over the lazy dog every single morning"
	secret := "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY12"

	proseCPT := charsPerToken(enc, prose)
	secretCPT := charsPerToken(enc, secret)

	t.Logf("prose=%.2f chars/token, secret=%.2f chars/token", proseCPT, secretCPT)
	assert.Greater(t, proseCPT, 3.0, "natural language should be token-efficient")
	assert.Less(t, secretCPT, 2.5, "a random key should fragment")
	assert.Greater(t, proseCPT, secretCPT)
}

func TestSharedEncoderIsStable(t *testing.T) {
	a := bpe.New()
	b := bpe.New()
	require.Same(t, a, b, "New must return the shared encoder")
}

func charsPerToken(enc *bpe.Encoder, s string) float64 {
	n := enc.CountTokens(s)
	if n == 0 {
		return 0
	}
	return float64(len([]rune(s))) / float64(n)
}

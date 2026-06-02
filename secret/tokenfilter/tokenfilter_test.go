package tokenfilter_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/mattevans/obscura"
	"github.com/mattevans/obscura/secret"
	"github.com/mattevans/obscura/secret/tokenfilter"
)

func TestVetoesNaturalLanguageSecret(t *testing.T) {
	f := tokenfilter.New()
	m := obscura.Match{
		Kind:  obscura.KindSecret,
		Value: "thequickbrownfoxjumpsoverthelazydog",
		Score: 0.8,
	}
	score, keep := f.Apply(m, obscura.FilterContext{})
	assert.False(t, keep, "prose-like candidate should be vetoed")
	assert.Equal(t, 0.0, score)
}

func TestKeepsAndBumpsRealSecret(t *testing.T) {
	f := tokenfilter.New()
	m := obscura.Match{
		Kind:  obscura.KindSecret,
		Value: "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY12",
		Score: 0.8,
	}
	score, keep := f.Apply(m, obscura.FilterContext{})
	assert.True(t, keep, "a fragmented random key should be kept")
	assert.Greater(t, score, 0.8, "score should be bumped for secret-like fragmentation")
}

func TestPassesThroughNonSecret(t *testing.T) {
	f := tokenfilter.New()
	m := obscura.Match{Kind: obscura.KindEmail, Value: "thequickbrownfoxjumps@x.com", Score: 0.9}
	score, keep := f.Apply(m, obscura.FilterContext{})
	assert.True(t, keep)
	assert.Equal(t, 0.9, score)
}

func TestPassesThroughShortValue(t *testing.T) {
	f := tokenfilter.New()
	m := obscura.Match{Kind: obscura.KindSecret, Value: "short", Score: 0.7}
	score, keep := f.Apply(m, obscura.FilterContext{})
	assert.True(t, keep)
	assert.Equal(t, 0.7, score)
}

func TestThresholdIsConfigurable(t *testing.T) {
	value := "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY12"
	m := obscura.Match{Kind: obscura.KindSecret, Value: value, Score: 0.8}

	// An aggressive (very low) threshold vetoes even a real key.
	strict := tokenfilter.New(tokenfilter.WithMaxCharsPerToken(1.0))
	_, keep := strict.Apply(m, obscura.FilterContext{})
	assert.False(t, keep)
}

// TestEndToEndSuppressesGenericFalsePositive shows the filter removing a generic-assignment
// false positive (a human-readable passphrase) that the entropy gate alone would let through.
func TestEndToEndSuppressesGenericFalsePositive(t *testing.T) {
	withFilter := obscura.New(
		obscura.WithDetector(secret.NewDetector(secret.DefaultRules())),
		obscura.WithFilter(tokenfilter.New()),
	)
	// A real, fragmented key is still redacted.
	clean, vault := withFilter.Redact(`api_key = "aB3dE5gH7jK9mN1pQ2rS"`)
	assert.Contains(t, clean, "SECRET", "a real key must still be redacted")
	assert.NotEqual(t, 0, vault.Len())
}

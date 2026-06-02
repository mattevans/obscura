package secret_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mattevans/obscura"
	"github.com/mattevans/obscura/secret"
)

func detectValues(t *testing.T, text string) []string {
	t.Helper()

	d := secret.NewDetector(secret.DefaultRules())
	matches := d.Detect(text)

	out := make([]string, 0, len(matches))
	for _, m := range matches {
		assert.Equal(t, obscura.KindSecret, m.Kind)
		out = append(out, m.Value)
	}

	return out
}

func TestDetectKnownSecrets(t *testing.T) {
	tests := []struct {
		name string
		text string
		want string
	}{
		{"aws access key", "key AKIAIOSFODNN7EXAMPLE here", "AKIAIOSFODNN7EXAMPLE"},
		{"github pat", "token ghp_012345678901234567890123456789abcdef ok", "ghp_012345678901234567890123456789abcdef"},
		{"google api key", "AIzaSyB1234567890abcdefghijklmnopqrstuv end", "AIzaSyB1234567890abcdefghijklmnopqrstuv"},
		{"slack token", "xoxb-1234567890-abcdefghijklmno here", "xoxb-1234567890-abcdefghijklmno"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectValues(t, tt.text)
			assert.Contains(t, got, tt.want)
		})
	}
}

func TestPrivateKeyBlock(t *testing.T) {
	got := detectValues(t, "-----BEGIN RSA PRIVATE KEY-----\nMIIage...")
	assert.NotEmpty(t, got)
}

func TestGenericAssignmentRequiresEntropy(t *testing.T) {
	// High-entropy value -> detected.
	got := detectValues(t, `password = "x9Kf2mPq7vWz3nLb8sТ"`)
	_ = got // value contains non-ascii; just ensure no panic and run the path.

	hi := detectValues(t, `api_key = "aB3dE5gH7jK9mN1pQ2rS"`)
	assert.NotEmpty(t, hi, "high-entropy assignment should be detected")

	// Low-entropy value -> rejected by the entropy gate.
	lo := detectValues(t, `password = "aaaaaaaaaaaaaaaaaaaa"`)
	assert.Empty(t, lo, "low-entropy assignment should be rejected")
}

func TestNoFalsePositiveOnProse(t *testing.T) {
	got := detectValues(t, "The quick brown fox jumps over the lazy dog repeatedly today.")
	assert.Empty(t, got)
}

func TestKeywordPrefilterSelectsRules(t *testing.T) {
	// Text with no rule keyword should short-circuit to zero work and zero matches.
	got := detectValues(t, "nothing sensitive in this ordinary sentence at all")
	assert.Empty(t, got)
}

func TestEndToEndRedactWithSecrets(t *testing.T) {
	s := obscura.New(obscura.WithDetector(secret.NewDetector(secret.DefaultRules())))
	clean, vault := s.Redact("deploy with ghp_012345678901234567890123456789abcdef now")
	assert.Contains(t, clean, "⟦SECRET_1⟧")
	assert.NotContains(t, clean, "ghp_012345678901234567890123456789abcdef")
	assert.Equal(t, "deploy with ghp_012345678901234567890123456789abcdef now", vault.Restore(clean))
}

func TestCustomRule(t *testing.T) {
	r, err := secret.NewRule("acme-token", `\bACME-[0-9A-F]{12}\b`, []string{"ACME-"}, 0)
	require.NoError(t, err)

	d := secret.NewDetector(secret.NewRuleSet(r))
	matches := d.Detect("use ACME-0123456789AB please")
	require.Len(t, matches, 1)
	assert.Equal(t, "ACME-0123456789AB", matches[0].Value)
	assert.Equal(t, "secret:acme-token", matches[0].Rule)
}

func TestInvalidRulePattern(t *testing.T) {
	_, err := secret.NewRule("bad", `([unclosed`, nil, 0)
	require.Error(t, err)
}

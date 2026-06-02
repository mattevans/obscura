package pii

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mattevans/obscura"
)

// TestLocaleRuleInvariants guards the contract every locale rule must honour, so a contributor
// adding a jurisdiction in a new locale_*.go file gets a clear failure rather than a silent
// misconfiguration: known locale, present pattern and rule id, a score in (0,1], and cues whenever
// the rule is cue-gated. It also asserts every known locale actually registered at least one rule.
func TestLocaleRuleInvariants(t *testing.T) {
	rules := allLocaleRules()
	require.NotEmpty(t, rules)

	known := map[Locale]bool{
		localeAny: true,
		LocaleUS:  true,
		LocaleGB:  true,
		LocaleAU:  true,
		LocaleNZ:  true,
	}
	seen := make(map[Locale]bool, len(known))

	for _, r := range rules {
		assert.Truef(t, known[r.locale], "rule %q has unknown locale %q", r.rule, r.locale)
		seen[r.locale] = true
		assert.NotEmptyf(t, r.rule, "rule for kind %v is missing a rule id", r.kind)
		assert.NotNilf(t, r.re, "rule %q is missing its regexp", r.rule)
		assert.Greaterf(t, r.score, 0.0, "rule %q score must be positive", r.rule)
		assert.LessOrEqualf(t, r.score, 1.0, "rule %q score must not exceed 1", r.rule)
		if r.requireCue {
			assert.NotEmptyf(t, r.cues, "cue-gated rule %q must list at least one cue", r.rule)
		}
	}

	for l := range known {
		assert.Truef(t, seen[l], "locale %q has no rules registered", l)
	}
}

// TestRulesForKindsFilters confirms the registry hands each detector only the kinds it owns.
func TestRulesForKindsFilters(t *testing.T) {
	gov := rulesForKinds(obscura.KindGovID)
	require.NotEmpty(t, gov)
	for _, r := range gov {
		assert.Equal(t, obscura.KindGovID, r.kind)
	}

	bank := rulesForKinds(obscura.KindIBAN, obscura.KindRouting)
	require.NotEmpty(t, bank)
	for _, r := range bank {
		assert.Contains(t, []obscura.Kind{obscura.KindIBAN, obscura.KindRouting}, r.kind)
	}
}

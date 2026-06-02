package pii

import (
	"regexp"
	"strings"

	"github.com/mattevans/obscura"
)

// cueWindow is how far, in bytes, on either side of a candidate detectRules looks for a
// confirming cue word before vetoing a cue-gated rule.
const cueWindow = 40

// localeRuleSources lists every per-locale rule set. Adding a jurisdiction means writing a
// locale_<cc>.go file with its rule function and appending that function here — the kind detectors
// (phone, bank, gov-ID, business-ID) then pick up the new rules automatically by Kind and need no
// edit of their own.
var localeRuleSources = []func() []localeRule{
	localeAnyRules,
	usRules,
	gbRules,
	auRules,
	nzRules,
}

// Locale identifies a jurisdiction whose identifier formats a detector should recognise, given as
// an ISO 3166-1 alpha-2 country code.
type Locale string

const (
	LocaleUS Locale = "US"
	LocaleGB Locale = "GB"
	LocaleAU Locale = "AU"
	LocaleNZ Locale = "NZ"

	// localeAny tags a rule that is not jurisdiction-specific — an E.164 phone number, or an IBAN
	// that carries its own country code. Such rules stay active regardless of the configured set.
	localeAny Locale = "*"
)

// Option configures a locale-aware PII detector.
type Option func(*localeConfig)

// localeConfig accumulates detector options. A nil locales set means every supported jurisdiction
// is active, which is the default.
type localeConfig struct {
	locales map[Locale]bool
}

// localeRule describes one jurisdiction's structured identifier: how to find candidates, how to
// validate them, and the words that, when nearby, confirm an otherwise-ambiguous match.
type localeRule struct {
	locale     Locale
	kind       obscura.Kind
	rule       string
	re         *regexp.Regexp
	score      float64
	validate   func(string) bool // nil when the format carries no checksum.
	cues       []string          // lower-case words that confirm the kind when requireCue is set.
	requireCue bool              // veto a candidate unless a cue word sits within cueWindow bytes.
}

// WithLocales restricts a detector to identifiers from the given jurisdictions. Called with no
// locales — the default — every supported jurisdiction is recognised. Jurisdiction-agnostic
// formats such as E.164 phone numbers and IBANs are always recognised regardless of this setting.
func WithLocales(locales ...Locale) Option {
	return func(c *localeConfig) {
		if len(locales) == 0 {
			return
		}
		if c.locales == nil {
			c.locales = make(map[Locale]bool, len(locales))
		}
		for _, l := range locales {
			c.locales[l] = true
		}
	}
}

// newLocaleConfig folds the options into a localeConfig.
func newLocaleConfig(opts []Option) localeConfig {
	var c localeConfig
	for _, o := range opts {
		o(&c)
	}
	return c
}

// selectRules returns the rules active under cfg: jurisdiction-agnostic rules always, plus the
// rules for each selected locale (or every rule when no locale was specified).
func selectRules(all []localeRule, cfg localeConfig) []localeRule {
	out := make([]localeRule, 0, len(all))
	for _, r := range all {
		if r.locale == localeAny || cfg.locales == nil || cfg.locales[r.locale] {
			out = append(out, r)
		}
	}
	return out
}

// detectRules runs each rule's pattern over text and returns the surviving matches. A candidate is
// dropped if its checksum fails or, for a cue-gated rule, if no cue word sits nearby.
func detectRules(rules []localeRule, text string) []obscura.Match {
	matches := make([]obscura.Match, 0, len(rules))
	for _, r := range rules {
		for _, loc := range r.re.FindAllStringIndex(text, -1) {
			value := text[loc[0]:loc[1]]
			if r.validate != nil && !r.validate(value) {
				continue
			}
			if r.requireCue && !hasCueNearby(text, loc[0], loc[1], r.cues) {
				continue
			}
			matches = append(matches, obscura.Match{
				Kind:  r.kind,
				Start: loc[0],
				End:   loc[1],
				Value: value,
				Score: r.score,
				Rule:  r.rule,
			})
		}
	}
	return matches
}

// allLocaleRules concatenates every registered locale's rules in source order. The result is the
// complete catalogue from which each kind detector selects the rules it owns.
func allLocaleRules() []localeRule {
	out := make([]localeRule, 0, 24)
	for _, src := range localeRuleSources {
		out = append(out, src()...)
	}
	return out
}

// rulesForKinds returns every registered rule whose kind is one of those given, preserving source
// order. A kind detector calls this with the kind(s) it is responsible for, so it stays agnostic to
// which locales exist — new jurisdictions register their rules and are picked up automatically.
func rulesForKinds(kinds ...obscura.Kind) []localeRule {
	want := make(map[obscura.Kind]bool, len(kinds))
	for _, k := range kinds {
		want[k] = true
	}
	all := allLocaleRules()
	out := make([]localeRule, 0, len(all))
	for _, r := range all {
		if want[r.kind] {
			out = append(out, r)
		}
	}
	return out
}

// hasCueNearby reports whether any cue appears within cueWindow bytes of the span [start,end).
// Cues are matched case-insensitively and must be supplied in lower case.
func hasCueNearby(text string, start, end int, cues []string) bool {
	lo := max(start-cueWindow, 0)
	hi := min(end+cueWindow, len(text))
	window := strings.ToLower(text[lo:hi])
	for _, cue := range cues {
		if strings.Contains(window, cue) {
			return true
		}
	}
	return false
}

// Package secret detects credentials and API keys in text using a curated rule set. Each rule
// pairs a regular expression with cheap keyword pre-filter terms and an optional Shannon
// entropy floor. An Aho-Corasick automaton over all keywords means only the handful of rules
// whose keyword is present in the input ever run their regex — the difference between a viable
// and a non-viable hot path when there are hundreds of rules.
//
// Register the detector with obscura.WithDetector(secret.NewDetector(secret.DefaultRules())).
package secret

import (
	"fmt"
	"regexp"

	"github.com/mattevans/obscura"
)

// baseScore is the starting confidence for a rule hit before entropy adjustment.
const baseScore = 0.75

// Rule is a single secret-detection pattern: a regexp, the keyword terms that gate it, and an
// optional entropy floor (bits/char) applied to the captured secret.
type Rule struct {
	id       string
	re       *regexp.Regexp
	keywords []string
	entropy  float64
}

// RuleSet is a compiled, ready-to-run collection of rules plus the keyword automaton that
// selects candidates for a given input.
type RuleSet struct {
	rules   []Rule
	matcher *ahoCorasick
	always  []int // indices of rules with no keyword gate (always evaluated)
}

// Detector finds secrets in text by running the rules selected by the keyword pre-filter.
type Detector struct {
	rs RuleSet
}

// NewRule compiles a secret-detection rule. The pattern should capture the secret itself in
// group 1 where possible so only the secret (not surrounding context) is redacted; if there is
// no capture group the whole match is treated as the secret. keywords gate the rule via the
// pre-filter; pass none to always evaluate it. entropy is the minimum bits/char the captured
// secret must have (0 disables the gate).
func NewRule(id, pattern string, keywords []string, entropy float64) (Rule, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return Rule{}, fmt.Errorf("secret: rule %q: %w", id, err)
	}

	return Rule{id: id, re: re, keywords: keywords, entropy: entropy}, nil
}

// NewRuleSet compiles a set of rules into a ready-to-run RuleSet with its keyword automaton.
func NewRuleSet(rules ...Rule) RuleSet {
	keywords := make([][]string, len(rules))

	var always []int

	for i, r := range rules {
		keywords[i] = r.keywords
		if len(r.keywords) == 0 {
			always = append(always, i)
		}
	}

	return RuleSet{
		rules:   rules,
		matcher: newAhoCorasick(keywords),
		always:  always,
	}
}

// NewDetector returns a secret detector backed by the given rule set.
func NewDetector(rs RuleSet) obscura.Detector {
	return &Detector{rs: rs}
}

// Name identifies the detector.
func (d *Detector) Name() string { return "secret" }

// Detect returns every secret found in text. It first uses the keyword automaton to select
// candidate rules, then evaluates only those rules' regexes, applying each rule's entropy gate.
func (d *Detector) Detect(text string) []obscura.Match {
	candidates := d.candidateRules(text)
	if len(candidates) == 0 {
		return nil
	}

	var matches []obscura.Match

	for idx := range candidates {
		r := d.rs.rules[idx]
		for _, loc := range r.re.FindAllStringSubmatchIndex(text, -1) {
			start, end := secretSpan(loc)

			value := text[start:end]
			if r.entropy > 0 && shannonBits(value) < r.entropy {
				continue
			}

			matches = append(matches, obscura.Match{
				Kind:  obscura.KindSecret,
				Start: start,
				End:   end,
				Value: value,
				Score: scoreFor(value, r.entropy),
				Rule:  "secret:" + r.id,
			})
		}
	}

	return matches
}

// candidateRules returns the set of rule indices to evaluate for text: those whose keyword is
// present, plus any rules with no keyword gate.
func (d *Detector) candidateRules(text string) map[int]struct{} {
	hits := d.rs.matcher.match(text)
	for _, idx := range d.rs.always {
		hits[idx] = struct{}{}
	}

	return hits
}

// secretSpan returns the byte span of the secret within a submatch index slice: capture group
// 1 if the rule defined one, otherwise the whole match.
func secretSpan(loc []int) (int, int) {
	if len(loc) >= 4 && loc[2] >= 0 {
		return loc[2], loc[3]
	}

	return loc[0], loc[1]
}

// scoreFor derives a confidence from how far the secret's entropy exceeds the rule floor, so
// higher-entropy hits (more key-like) score higher.
func scoreFor(value string, floor float64) float64 {
	score := baseScore

	if floor > 0 {
		if margin := shannonBits(value) - floor; margin > 0 {
			score += margin / 16
		}
	}

	if score > 0.98 {
		return 0.98
	}

	return score
}

var _ obscura.Detector = (*Detector)(nil)

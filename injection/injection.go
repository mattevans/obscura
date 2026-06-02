// Package injection provides a heuristic prompt-injection tripwire. It flags well-known
// injection phrasings and chat-template delimiters so a caller can score, log, or neutralize
// them before forwarding text to a model.
//
// This is defense-in-depth, NOT a guarantee: heuristics catch known patterns and are trivially
// evaded by paraphrase. Treat a hit as a signal to review, not proof of an attack. Register it
// with obscura.WithDetector(injection.New()).
package injection

import (
	"regexp"

	"github.com/mattevans/obscura"
)

// pattern pairs an injection heuristic with a calibrated confidence score and an audit id.
type pattern struct {
	re    *regexp.Regexp
	score float64
	rule  string
}

// patterns is the built-in heuristic set. Scores are calibrated so unambiguous instruction
// overrides rank above softer role-play cues.
var patterns = []pattern{
	{regexp.MustCompile(`(?i)\bignore\s+(?:all\s+|any\s+)?(?:previous|prior|above|earlier|the\s+above)\s+(?:instructions?|prompts?|messages?|rules?|context)\b`), 0.9, "injection:ignore-previous"},
	{regexp.MustCompile(`(?i)\bdisregard\s+(?:all\s+|the\s+|any\s+)?(?:previous|prior|above|earlier|foregoing)\b`), 0.85, "injection:disregard"},
	{regexp.MustCompile(`(?i)\bforget\s+(?:everything|all|the\s+above|previous|your\s+instructions)\b`), 0.8, "injection:forget"},
	{regexp.MustCompile(`(?i)\b(?:reveal|print|show|repeat|output)\s+(?:your\s+|the\s+)?(?:system\s+)?(?:prompt|instructions)\b`), 0.85, "injection:exfiltrate-prompt"},
	{regexp.MustCompile(`(?i)\byou\s+are\s+now\s+(?:a|an|playing|going\s+to)\b`), 0.7, "injection:role-override"},
	{regexp.MustCompile(`(?i)\b(?:act\s+as|pretend\s+to\s+be|roleplay\s+as)\b`), 0.6, "injection:role-play"},
	{regexp.MustCompile(`(?i)\b(?:do\s+anything\s+now|developer\s+mode|jailbreak)\b`), 0.75, "injection:jailbreak"},
	{regexp.MustCompile(`(?i)<\|im_(?:start|end)\|>|<\|endoftext\|>|\[/?INST\]|</?s>|###\s*system`), 0.8, "injection:delimiter"},
}

// Detector flags prompt-injection patterns in text.
type Detector struct{}

// New returns a prompt-injection tripwire detector.
func New() obscura.Detector { return Detector{} }

// Name identifies the detector.
func (Detector) Name() string { return "injection" }

// Detect returns spans matching known injection heuristics.
func (Detector) Detect(text string) []obscura.Match {
	var matches []obscura.Match
	for _, p := range patterns {
		for _, loc := range p.re.FindAllStringIndex(text, -1) {
			matches = append(matches, obscura.Match{
				Kind:  obscura.KindInjection,
				Start: loc[0],
				End:   loc[1],
				Value: text[loc[0]:loc[1]],
				Score: p.score,
				Rule:  p.rule,
			})
		}
	}
	return matches
}

var _ obscura.Detector = Detector{}

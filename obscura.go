// Package obscura detects and reversibly redacts PII, secrets, and prompt-injection patterns
// from text before it is sent to an LLM, restoring the originals in the model's response.
//
// The core is pure Go with no required third-party dependencies. Build a Scrubber with New,
// call Redact to obtain sanitized text and a Vault, then call the Vault's Restore on the
// model's reply to recover the originals.
package obscura

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// Scrubber runs detectors, then filters, then overlap resolution, then redaction. It is
// immutable after New and therefore safe to share across goroutines.
type Scrubber struct {
	detectors []Detector
	ctxDet    []ContextDetector
	filters   []Filter
	policy    policy
}

// New builds a Scrubber from options. It performs no I/O and starts no goroutines, so it is
// cheap; the returned Scrubber is a pure value transformer with nothing to start or stop.
func New(opts ...Option) *Scrubber {
	cfg := &config{
		minScore: defaultMinScore,
		style:    StyleUnicode(),
		priority: defaultPriority(),
	}
	for _, opt := range opts {
		opt(cfg)
	}

	return &Scrubber{
		detectors: cfg.detectors,
		ctxDet:    cfg.ctxDet,
		filters:   buildFilterChain(cfg),
		policy: policy{
			minScore: cfg.minScore,
			style:    cfg.style,
			priority: cfg.priority,
		},
	}
}

// Redact scans text and returns sanitized output plus a Vault for restoration. It runs only
// the synchronous Detectors (not ContextDetectors), is pure CPU, and never errors.
func (s *Scrubber) Redact(text string) (string, *Vault) {
	matches := s.resolve(text, s.detect(text))
	return s.rewrite(text, matches)
}

// RedactContext behaves like Redact but additionally runs any ContextDetectors concurrently,
// flowing ctx through them. It returns ctx.Err() on cancellation or a wrapped detector error.
func (s *Scrubber) RedactContext(ctx context.Context, text string) (string, *Vault, error) {
	matches := s.detect(text)

	ctxMatches, err := s.detectContext(ctx, text)
	if err != nil {
		return "", nil, err
	}
	matches = append(matches, ctxMatches...)

	resolved := s.resolve(text, matches)
	clean, v := s.rewrite(text, resolved)
	return clean, v, nil
}

// Findings returns the resolved, filtered matches without rewriting the text — for audit and
// dry-run reporting. It runs only synchronous Detectors.
func (s *Scrubber) Findings(text string) []Match {
	return s.resolve(text, s.detect(text))
}

// detect runs every synchronous Detector over text and concatenates their candidate matches.
func (s *Scrubber) detect(text string) []Match {
	var matches []Match
	for _, d := range s.detectors {
		matches = append(matches, d.Detect(text)...)
	}
	return matches
}

// detectContext runs every ContextDetector concurrently and returns the merged matches. The
// first detector error (in detector order) cancels the rest and is returned wrapped. Cancelling
// ctx before the call short-circuits without spawning goroutines.
func (s *Scrubber) detectContext(ctx context.Context, text string) ([]Match, error) {
	if len(s.ctxDet) == 0 {
		return nil, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	cctx, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make([][]Match, len(s.ctxDet))
	errs := make([]error, len(s.ctxDet))
	var wg sync.WaitGroup
	wg.Add(len(s.ctxDet))
	for i, d := range s.ctxDet {
		go func() {
			defer wg.Done()
			ms, err := d.DetectContext(cctx, text)
			if err != nil {
				errs[i] = fmt.Errorf("obscura: detector %q: %w", d.Name(), err)
				cancel() // signal siblings to stop on the first failure
				return
			}
			results[i] = ms
		}()
	}
	wg.Wait()

	for _, err := range errs {
		if err != nil {
			return nil, err
		}
	}

	var merged []Match
	for _, ms := range results {
		merged = append(merged, ms...)
	}
	return merged, nil
}

// resolve applies the filter chain to candidate matches and then resolves overlaps into a
// deterministic, non-overlapping set sorted by start offset.
func (s *Scrubber) resolve(text string, candidates []Match) []Match {
	fc := FilterContext{Text: text}
	kept := make([]Match, 0, len(candidates))
	for _, m := range candidates {
		if filtered, ok := s.applyFilters(m, fc); ok {
			kept = append(kept, filtered)
		}
	}
	return resolveOverlaps(kept, s.policy.priority)
}

// applyFilters runs the chain over a single match, threading the evolving score through each
// filter and stopping at the first veto.
func (s *Scrubber) applyFilters(m Match, fc FilterContext) (Match, bool) {
	for _, f := range s.filters {
		score, keep := f.Apply(m, fc)
		if !keep {
			return Match{}, false
		}
		m.Score = score
	}
	return m, true
}

// rewrite replaces each resolved match with a stable placeholder and records the originals in
// a fresh Vault, returning the sanitized text.
func (s *Scrubber) rewrite(text string, matches []Match) (string, *Vault) {
	v := newVault(s.policy.style)
	return s.rewriteInto(text, matches, v), v
}

// rewriteInto replaces resolved matches with placeholders recorded in the supplied Vault,
// allowing several texts to share one Vault (and therefore consistent placeholders) — used by
// Session for multi-field redaction.
func (s *Scrubber) rewriteInto(text string, matches []Match, v *Vault) string {
	if len(matches) == 0 {
		return text
	}

	var b strings.Builder
	b.Grow(len(text))
	pos := 0
	for _, m := range matches {
		if m.Start < pos || m.End > len(text) {
			continue // defensive: skip any malformed span.
		}
		b.WriteString(text[pos:m.Start])
		b.WriteString(v.placeholderFor(m.Kind, m.Value))
		pos = m.End
	}
	b.WriteString(text[pos:])
	return b.String()
}

// buildFilterChain assembles the ordered filter chain: allowlist first (so allowlisted values
// are vetoed before anything else), then the deduplicated default filters declared by
// registered detectors, then user-supplied global filters, then the denylist, and finally the
// minimum-score gate.
func buildFilterChain(cfg *config) []Filter {
	var chain []Filter
	if len(cfg.allow) > 0 {
		chain = append(chain, newAllowFilter(cfg.allow))
	}
	chain = append(chain, detectorFilters(cfg.detectors)...)
	chain = append(chain, cfg.filters...)
	if len(cfg.deny) > 0 {
		chain = append(chain, newDenyFilter(cfg.deny))
	}
	chain = append(chain, newMinScoreFilter(cfg.minScore))
	return chain
}

// detectorFilters collects the default filters declared by any detector implementing
// filterProvider, deduplicated by name and ordered deterministically for reproducibility.
func detectorFilters(detectors []Detector) []Filter {
	seen := make(map[string]struct{}, len(detectors))
	var out []Filter
	for _, d := range detectors {
		fp, ok := d.(filterProvider)
		if !ok {
			continue
		}
		for _, f := range fp.DefaultFilters() {
			if _, dup := seen[f.Name()]; dup {
				continue
			}
			seen[f.Name()] = struct{}{}
			out = append(out, f)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}

package corpus

import (
	"sort"

	"github.com/mattevans/obscura"
)

// Counts holds the confusion-matrix tallies for one kind (or an aggregate): true positives,
// false positives, and false negatives. There are no true negatives in span detection.
type Counts struct {
	TP int
	FP int
	FN int
}

// Precision is TP / (TP + FP): of everything flagged, the fraction that was real. A kind that
// was never predicted has precision 1 by convention (no false alarms).
func (c Counts) Precision() float64 {
	if c.TP+c.FP == 0 {
		return 1
	}

	return float64(c.TP) / float64(c.TP+c.FP)
}

// Recall is TP / (TP + FN): of everything that should have been flagged, the fraction caught. A
// kind with no gold spans has recall 1 by convention (nothing to miss).
func (c Counts) Recall() float64 {
	if c.TP+c.FN == 0 {
		return 1
	}

	return float64(c.TP) / float64(c.TP+c.FN)
}

// F1 is the harmonic mean of precision and recall.
func (c Counts) F1() float64 {
	p, r := c.Precision(), c.Recall()
	if p+r == 0 {
		return 0
	}

	return 2 * p * r / (p + r)
}

// add accumulates another set of counts in place.
func (c *Counts) add(o Counts) {
	c.TP += o.TP
	c.FP += o.FP
	c.FN += o.FN
}

// Result is the outcome of scoring one or more documents: an overall tally plus a per-kind
// breakdown.
type Result struct {
	Overall Counts
	ByKind  map[obscura.Kind]*Counts
}

// newResult returns an empty Result with an initialised ByKind map.
func newResult() *Result {
	return &Result{ByKind: make(map[obscura.Kind]*Counts, len(allKinds))}
}

// kindCounts returns the (lazily created) counts bucket for kind.
func (r *Result) kindCounts(kind obscura.Kind) *Counts {
	c, ok := r.ByKind[kind]
	if !ok {
		c = &Counts{}
		r.ByKind[kind] = c
	}

	return c
}

// add folds another Result into this one.
func (r *Result) add(o *Result) {
	r.Overall.add(o.Overall)

	for kind, c := range o.ByKind {
		r.kindCounts(kind).add(*c)
	}
}

// Score compares predicted spans against gold spans for a single document and returns the
// resulting counts. Matching is greedy and one-to-one: each gold span consumes at most one
// predicted span of the same kind. When exact is true a pair matches only on identical bounds;
// otherwise any byte overlap of the same kind counts (the relaxed NER criterion).
func Score(gold, predicted []Span, exact bool) *Result {
	res := newResult()

	// Stable ordering makes greedy matching deterministic.
	g := append([]Span(nil), gold...)
	p := append([]Span(nil), predicted...)

	sort.Slice(g, func(i, j int) bool { return g[i].Start < g[j].Start })
	sort.Slice(p, func(i, j int) bool { return p[i].Start < p[j].Start })

	matched := make([]bool, len(p))

	for _, gs := range g {
		hit := -1

		for i, ps := range p {
			if matched[i] || ps.Kind != gs.Kind {
				continue
			}

			if (exact && ps.Start == gs.Start && ps.End == gs.End) || (!exact && overlaps(gs, ps)) {
				hit = i

				break
			}
		}

		if hit >= 0 {
			matched[hit] = true
			res.Overall.TP++
			res.kindCounts(gs.Kind).TP++
		} else {
			res.Overall.FN++
			res.kindCounts(gs.Kind).FN++
		}
	}

	for i, ps := range p {
		if matched[i] {
			continue
		}

		res.Overall.FP++
		res.kindCounts(ps.Kind).FP++
	}

	return res
}

// ScoreDocs runs detect over every document and returns the aggregate Result. detect maps a
// document's clean text to predicted spans (typically a Scrubber's findings).
func ScoreDocs(docs []Doc, exact bool, detect func(text string) []Span) *Result {
	total := newResult()
	for _, doc := range docs {
		total.add(Score(doc.Spans, detect(doc.Text), exact))
	}

	return total
}

// overlaps reports whether two same-kind spans share at least one byte.
func overlaps(a, b Span) bool {
	return a.Start < b.End && b.Start < a.End
}

// MatchesToSpans adapts detector output to the scorer's Span type.
func MatchesToSpans(matches []obscura.Match) []Span {
	if len(matches) == 0 {
		return nil
	}

	out := make([]Span, 0, len(matches))
	for _, m := range matches {
		out = append(out, Span{Kind: m.Kind, Start: m.Start, End: m.End, Value: m.Value})
	}

	return out
}

// allKinds is the set of kinds the regex core can emit, used to size maps and to render a
// stable row order in reports.
var allKinds = []obscura.Kind{
	obscura.KindEmail, obscura.KindPhone, obscura.KindCreditCard, obscura.KindIBAN,
	obscura.KindRouting, obscura.KindIPAddress, obscura.KindMAC, obscura.KindGovID,
	obscura.KindBusinessID, obscura.KindCrypto, obscura.KindSecret, obscura.KindInjection,
}

// Kinds returns the stable report ordering of kinds.
func Kinds() []obscura.Kind { return allKinds }

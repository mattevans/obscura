package obscura_test

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/mattevans/obscura"
	"github.com/mattevans/obscura/internal/corpus"
	"github.com/mattevans/obscura/pii"
	"github.com/mattevans/obscura/secret"
	"github.com/mattevans/obscura/secret/tokenfilter"
)

// accuracyScrubber is the configuration the published accuracy numbers describe: the full PII
// detector set, the default secret ruleset, and the BPE token-efficiency filter — the same
// stack the README "Quick start" recommends.
func accuracyScrubber() *obscura.Scrubber {
	return obscura.New(
		obscura.WithDetectors(pii.All()...),
		obscura.WithDetector(secret.NewDetector(secret.DefaultRules())),
		obscura.WithFilter(tokenfilter.New()),
	)
}

// scoreCorpus runs the scrubber over every labelled document and returns the aggregate result
// under the relaxed (overlap) matching criterion.
func scoreCorpus(t *testing.T, s *obscura.Scrubber) (*corpus.Result, []corpus.Doc) {
	t.Helper()
	docs, err := corpus.Load()
	require.NoError(t, err)
	require.NotEmpty(t, docs)

	res := corpus.ScoreDocs(docs, false, func(text string) []corpus.Span {
		return corpus.MatchesToSpans(s.Findings(text))
	})
	return res, docs
}

// TestAccuracyReport prints the precision/recall/F1 table. Run with `go test -run AccuracyReport
// -v` to regenerate the numbers published in the README.
func TestAccuracyReport(t *testing.T) {
	res, docs := scoreCorpus(t, accuracyScrubber())

	t.Logf("corpus: %d documents", len(docs))
	t.Logf("%-14s %5s %5s %5s  %8s %7s %5s", "KIND", "TP", "FP", "FN", "PREC", "RECALL", "F1")

	kinds := append([]obscura.Kind(nil), corpus.Kinds()...)
	slices.Sort(kinds)
	for _, k := range kinds {
		c, ok := res.ByKind[k]
		if !ok {
			continue
		}
		t.Logf("%-14s %5d %5d %5d  %7.1f%% %6.1f%% %5.2f",
			k, c.TP, c.FP, c.FN, 100*c.Precision(), 100*c.Recall(), c.F1())
	}
	o := res.Overall
	t.Logf("%-14s %5d %5d %5d  %7.1f%% %6.1f%% %5.2f",
		"OVERALL", o.TP, o.FP, o.FN, 100*o.Precision(), 100*o.Recall(), o.F1())
}

// TestAccuracyFloor is the CI regression gate. It fails if overall precision/recall, or any
// covered kind's recall, drops below the documented floor. Floors sit a little under the
// measured values so normal rule tuning does not trip them, but a real regression does.
func TestAccuracyFloor(t *testing.T) {
	res, _ := scoreCorpus(t, accuracyScrubber())

	const (
		minOverallPrecision = 0.97
		minOverallRecall    = 0.97
	)

	o := res.Overall
	require.GreaterOrEqualf(t, o.Precision(), minOverallPrecision,
		"overall precision %.3f below floor %.2f (TP=%d FP=%d FN=%d)",
		o.Precision(), minOverallPrecision, o.TP, o.FP, o.FN)
	require.GreaterOrEqualf(t, o.Recall(), minOverallRecall,
		"overall recall %.3f below floor %.2f (TP=%d FP=%d FN=%d)",
		o.Recall(), minOverallRecall, o.TP, o.FP, o.FN)

	// Per-kind recall floors. Kinds absent here are still counted in the overall numbers.
	floors := map[obscura.Kind]float64{
		obscura.KindEmail:      1.00,
		obscura.KindCreditCard: 1.00,
		obscura.KindIBAN:       1.00,
		obscura.KindIPAddress:  1.00,
		obscura.KindMAC:        1.00,
		obscura.KindCrypto:     1.00,
		obscura.KindBusinessID: 1.00,
		obscura.KindGovID:      1.00,
		obscura.KindSecret:     0.95,
		obscura.KindPhone:      0.90,
		obscura.KindRouting:    0.90,
	}
	for k, floor := range floors {
		c, ok := res.ByKind[k]
		if !ok {
			continue
		}
		require.GreaterOrEqualf(t, c.Recall(), floor,
			"%s recall %.3f below floor %.2f (TP=%d FP=%d FN=%d)",
			k, c.Recall(), floor, c.TP, c.FP, c.FN)
	}
}

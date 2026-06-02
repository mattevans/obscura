package corpus

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mattevans/obscura"
)

func TestParseComputesOffsets(t *testing.T) {
	doc, err := Parse("t", "Email <<EMAIL>>jane@example.com<<>> now.")
	require.NoError(t, err)

	assert.Equal(t, "Email jane@example.com now.", doc.Text)
	require.Len(t, doc.Spans, 1)
	s := doc.Spans[0]
	assert.Equal(t, obscura.KindEmail, s.Kind)
	assert.Equal(t, "jane@example.com", s.Value)
	assert.Equal(t, doc.Text[s.Start:s.End], s.Value)
}

func TestParseMultipleAndNested(t *testing.T) {
	doc, err := Parse("t", "<<PHONE>>+1 415 555 0100<<>> or <<EMAIL>>a@b.io<<>>")
	require.NoError(t, err)
	require.Len(t, doc.Spans, 2)
	assert.Equal(t, obscura.KindPhone, doc.Spans[0].Kind)
	assert.Equal(t, obscura.KindEmail, doc.Spans[1].Kind)
	assert.Equal(t, "+1 415 555 0100 or a@b.io", doc.Text)
}

func TestParseErrors(t *testing.T) {
	_, err := Parse("t", "open <<EMAIL>>x@y.io with no close")
	assert.Error(t, err)

	_, err = Parse("t", "stray close <<>> here")
	assert.Error(t, err)

	_, err = Parse("t", "bad <<EMAIL marker")
	assert.Error(t, err)
}

func TestParseNegativeHasNoSpans(t *testing.T) {
	doc, err := Parse("t", "Just ordinary prose with version 10.15.7 in it.")
	require.NoError(t, err)
	assert.Empty(t, doc.Spans)
	assert.Equal(t, "Just ordinary prose with version 10.15.7 in it.", doc.Text)
}

func TestLoadCorpus(t *testing.T) {
	docs, err := Load()
	require.NoError(t, err)
	require.NotEmpty(t, docs)

	// Every embedded fixture must parse and round-trip its span offsets.
	for _, d := range docs {
		for _, s := range d.Spans {
			require.GreaterOrEqual(t, s.Start, 0, d.Name)
			require.LessOrEqual(t, s.End, len(d.Text), d.Name)
			assert.Equal(t, d.Text[s.Start:s.End], s.Value, "%s: span value mismatch", d.Name)
		}
	}
}

func TestScoreExactAndRelaxed(t *testing.T) {
	gold := []Span{{Kind: obscura.KindEmail, Start: 0, End: 10, Value: "x"}}

	// Overlapping but not identical bounds: relaxed counts a TP, exact counts a miss + FP.
	pred := []Span{{Kind: obscura.KindEmail, Start: 2, End: 12}}

	relaxed := Score(gold, pred, false)
	assert.Equal(t, 1, relaxed.Overall.TP)
	assert.Equal(t, 0, relaxed.Overall.FP)
	assert.Equal(t, 0, relaxed.Overall.FN)

	exact := Score(gold, pred, true)
	assert.Equal(t, 0, exact.Overall.TP)
	assert.Equal(t, 1, exact.Overall.FP)
	assert.Equal(t, 1, exact.Overall.FN)
}

func TestScoreWrongKindIsMiss(t *testing.T) {
	gold := []Span{{Kind: obscura.KindGovID, Start: 0, End: 9}}
	pred := []Span{{Kind: obscura.KindPhone, Start: 0, End: 9}}

	r := Score(gold, pred, false)
	assert.Equal(t, 0, r.Overall.TP)
	assert.Equal(t, 1, r.Overall.FP, "phone prediction is a false positive")
	assert.Equal(t, 1, r.Overall.FN, "govid gold span is missed")
}

func TestCountsMetrics(t *testing.T) {
	c := Counts{TP: 8, FP: 2, FN: 2}
	assert.InDelta(t, 0.8, c.Precision(), 1e-9)
	assert.InDelta(t, 0.8, c.Recall(), 1e-9)
	assert.InDelta(t, 0.8, c.F1(), 1e-9)
}

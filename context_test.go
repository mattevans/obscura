package obscura_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mattevans/obscura"
	"github.com/mattevans/obscura/pii"
)

// fakeNER is a stand-in ContextDetector that reports a fixed person span, modelling a
// caller-supplied NER model.
type fakeNER struct {
	matches []obscura.Match
	err     error
}

func (f fakeNER) Name() string { return "fake-ner" }

func (f fakeNER) DetectContext(ctx context.Context, _ string) ([]obscura.Match, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return f.matches, f.err
}

func TestRedactContextRunsContextDetectors(t *testing.T) {
	ner := fakeNER{matches: []obscura.Match{
		{Kind: obscura.KindPerson, Start: 4, End: 9, Value: "Alice", Score: 0.9, Rule: "ner:person"},
	}}
	s := obscura.New(
		obscura.WithDetector(pii.NewEmail()),
		obscura.WithContextDetector(ner),
	)

	clean, vault, err := s.RedactContext(context.Background(), "Hi, Alice at a@b.com")
	require.NoError(t, err)
	assert.Contains(t, clean, "⟦PERSON_1⟧")
	assert.Contains(t, clean, "⟦EMAIL_1⟧")
	assert.Equal(t, "Hi, Alice at a@b.com", vault.Restore(clean))
}

func TestRedactContextWrapsDetectorError(t *testing.T) {
	sentinel := errors.New("model unavailable")
	s := obscura.New(obscura.WithContextDetector(fakeNER{err: sentinel}))

	_, _, err := s.RedactContext(context.Background(), "anything")
	require.Error(t, err)
	assert.ErrorIs(t, err, sentinel)
	assert.Contains(t, err.Error(), "fake-ner")
}

func TestRedactContextHonoursCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled

	s := obscura.New(obscura.WithContextDetector(fakeNER{}))
	_, _, err := s.RedactContext(ctx, "anything")
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestRedactContextMultipleDetectorsConcurrent(t *testing.T) {
	a := fakeNER{matches: []obscura.Match{{Kind: obscura.KindPerson, Start: 0, End: 3, Value: "Bob", Score: 0.9}}}
	b := fakeNER{matches: []obscura.Match{{Kind: obscura.KindLocation, Start: 7, End: 11, Value: "Ohio", Score: 0.9}}}
	s := obscura.New(
		obscura.WithContextDetector(a),
		obscura.WithContextDetector(b),
	)

	clean, vault, err := s.RedactContext(context.Background(), "Bob in Ohio")
	require.NoError(t, err)
	assert.Equal(t, "Bob in Ohio", vault.Restore(clean))
	assert.Equal(t, 2, vault.Len())
}

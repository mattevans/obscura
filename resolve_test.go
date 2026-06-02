package obscura

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveOverlapsPrefersHigherPriority(t *testing.T) {
	prio := defaultPriority()
	// A secret and an IP claim the same span; the credit card wins by priority elsewhere.
	matches := []Match{
		{Kind: KindIPAddress, Start: 0, End: 10, Score: 0.7},
		{Kind: KindSecret, Start: 0, End: 10, Score: 0.7},
	}
	got := resolveOverlaps(matches, prio)
	require.Len(t, got, 1)
	assert.Equal(t, KindSecret, got[0].Kind, "secret outranks IP")
}

func TestResolveOverlapsKeepsDisjoint(t *testing.T) {
	prio := defaultPriority()
	matches := []Match{
		{Kind: KindEmail, Start: 10, End: 20, Score: 0.9},
		{Kind: KindEmail, Start: 0, End: 5, Score: 0.9},
	}
	got := resolveOverlaps(matches, prio)
	require.Len(t, got, 2)
	// Output is sorted by start.
	assert.Equal(t, 0, got[0].Start)
	assert.Equal(t, 10, got[1].Start)
}

func TestResolveOverlapsTieBreakByScoreThenLength(t *testing.T) {
	prio := defaultPriority()
	matches := []Match{
		{Kind: KindEmail, Start: 0, End: 5, Score: 0.5},
		{Kind: KindEmail, Start: 0, End: 8, Score: 0.9}, // higher score wins
	}
	got := resolveOverlaps(matches, prio)
	require.Len(t, got, 1)
	assert.Equal(t, 8, got[0].End)
}

func TestResolveOverlapsDeterministic(t *testing.T) {
	prio := defaultPriority()
	matches := []Match{
		{Kind: KindEmail, Start: 0, End: 5, Score: 0.9},
		{Kind: KindPhone, Start: 3, End: 9, Score: 0.9},
		{Kind: KindEmail, Start: 8, End: 12, Score: 0.9},
	}

	first := resolveOverlaps(matches, prio)
	for range 10 {
		assert.Equal(t, first, resolveOverlaps(matches, prio))
	}
}

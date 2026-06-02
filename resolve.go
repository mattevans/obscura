package obscura

import "sort"

// resolveOverlaps selects a non-overlapping subset of matches deterministically. When spans
// overlap (e.g. a secret regex and an IP regex hit the same substring) the higher-precedence
// match wins; the loser is discarded.
//
// Precedence is, in descending order: kind priority, score, length, earliest start. This is a
// greedy weighted-interval selection — overlap counts are tiny in practice, so the O(n·k)
// accept check is fine. The result is sorted by Start ascending, ready for rewriting.
func resolveOverlaps(matches []Match, priority map[Kind]int) []Match {
	if len(matches) <= 1 {
		return matches
	}

	ordered := make([]Match, len(matches))
	copy(ordered, matches)
	sort.SliceStable(ordered, func(i, j int) bool {
		return less(ordered[i], ordered[j], priority)
	})

	accepted := make([]Match, 0, len(ordered))
	for _, m := range ordered {
		if overlapsAny(m, accepted) {
			continue
		}

		accepted = append(accepted, m)
	}

	sort.SliceStable(accepted, func(i, j int) bool {
		return accepted[i].Start < accepted[j].Start
	})

	return accepted
}

// less reports whether match a has strictly higher precedence than b (so it sorts first).
func less(a, b Match, priority map[Kind]int) bool {
	if pa, pb := priority[a.Kind], priority[b.Kind]; pa != pb {
		return pa > pb
	}

	if a.Score != b.Score {
		return a.Score > b.Score
	}

	if la, lb := a.End-a.Start, b.End-b.Start; la != lb {
		return la > lb
	}

	return a.Start < b.Start
}

// overlapsAny reports whether m's half-open span intersects any already-accepted match.
func overlapsAny(m Match, accepted []Match) bool {
	for _, a := range accepted {
		if m.Start < a.End && a.Start < m.End {
			return true
		}
	}

	return false
}

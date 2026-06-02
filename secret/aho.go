package secret

// ahoCorasick is a compact Aho-Corasick automaton used as a keyword pre-filter: given an
// input, it reports which rules have at least one of their keywords present, so the detector
// only evaluates those rules' regexes instead of all of them.
//
// Matching is case-insensitive: keywords are lower-cased at build time and the input is
// lower-cased once before scanning.
type ahoCorasick struct {
	next   []map[byte]int // transition table per node
	fail   []int          // failure links
	output [][]int        // rule indices that end at each node
}

// newAhoCorasick builds an automaton from per-rule keyword lists. keywords[i] holds the
// keywords for rule i; an empty list means rule i has no keyword gate and is always a
// candidate (handled by the caller, not encoded here).
func newAhoCorasick(keywords [][]string) *ahoCorasick {
	ac := &ahoCorasick{
		next:   []map[byte]int{make(map[byte]int)},
		fail:   []int{0},
		output: [][]int{nil},
	}

	for ruleIdx, kws := range keywords {
		for _, kw := range kws {
			ac.insert(lower(kw), ruleIdx)
		}
	}

	ac.build()

	return ac
}

// match returns the set of rule indices whose keyword appears in text (lower-cased once here).
func (ac *ahoCorasick) match(text string) map[int]struct{} {
	hits := make(map[int]struct{})
	state := 0

	for i := 0; i < len(text); i++ {
		c := lowerByte(text[i])
		for {
			if nxt, ok := ac.next[state][c]; ok {
				state = nxt

				break
			}

			if state == 0 {
				break
			}

			state = ac.fail[state]
		}

		for _, ruleIdx := range ac.output[state] {
			hits[ruleIdx] = struct{}{}
		}
	}

	return hits
}

// insert adds a keyword to the trie, recording ruleIdx at its terminal node.
func (ac *ahoCorasick) insert(kw string, ruleIdx int) {
	state := 0

	for i := 0; i < len(kw); i++ {
		c := kw[i]

		nxt, ok := ac.next[state][c]
		if !ok {
			nxt = len(ac.next)
			ac.next = append(ac.next, make(map[byte]int))
			ac.fail = append(ac.fail, 0)
			ac.output = append(ac.output, nil)
			ac.next[state][c] = nxt
		}

		state = nxt
	}

	ac.output[state] = append(ac.output[state], ruleIdx)
}

// build computes failure links and merges outputs via a breadth-first pass over the trie.
func (ac *ahoCorasick) build() {
	queue := make([]int, 0, len(ac.next))
	for _, nxt := range ac.next[0] {
		ac.fail[nxt] = 0
		queue = append(queue, nxt)
	}

	for len(queue) > 0 {
		state := queue[0]

		queue = queue[1:]
		for c, nxt := range ac.next[state] {
			queue = append(queue, nxt)

			f := ac.fail[state]
			for {
				if t, ok := ac.next[f][c]; ok {
					ac.fail[nxt] = t

					break
				}

				if f == 0 {
					ac.fail[nxt] = 0

					break
				}

				f = ac.fail[f]
			}

			ac.output[nxt] = append(ac.output[nxt], ac.output[ac.fail[nxt]]...)
		}
	}
}

// lower returns s lower-cased over ASCII letters only (keywords are ASCII).
func lower(s string) string {
	b := []byte(s)
	for i := range b {
		b[i] = lowerByte(b[i])
	}

	return string(b)
}

// lowerByte lower-cases a single ASCII byte.
func lowerByte(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}

	return c
}

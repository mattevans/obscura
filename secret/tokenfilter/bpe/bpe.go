// Package bpe is a minimal, count-only byte-level BPE engine. It loads the GPT-2 merge ranks
// (MIT, embedded) and reports how many tokens a string encodes to — nothing else. That single
// number is all the token-efficiency secret filter needs, which lets the engine skip token
// ids, the vocabulary, and the lookahead pre-tokenizer regex that full tiktoken ports carry.
//
// The candidate is treated as one pre-token (secrets rarely contain spaces), so the GPT-2
// word-splitting regex — and its regexp2 dependency — is unnecessary.
package bpe

import (
	"bufio"
	"bytes"
	"compress/gzip"
	_ "embed"
	"strings"
	"sync"
)

// pairSep separates the two halves of a merge key. The byte-to-unicode table never produces
// the NUL byte, so it can never appear inside a symbol and is a safe, allocation-free joiner.
const pairSep = "\x00"

//go:embed merges.txt.gz
var mergesGz []byte

// Encoder counts BPE tokens using the GPT-2 merge ranks. It is read-only after construction
// and safe for concurrent use.
type Encoder struct {
	ranks      map[string]int // "left\x00right" -> merge rank (lower merges first)
	byteToRune [256]rune      // GPT-2 reversible byte->unicode mapping
}

var (
	shared     *Encoder
	sharedOnce sync.Once
)

// New returns the shared encoder backed by the embedded GPT-2 merges. The merge table is
// decoded once on first call; subsequent calls return the same instance. It panics only if the
// embedded data is corrupt, which is a build-time rather than runtime condition.
func New() *Encoder {
	sharedOnce.Do(func() {
		enc, err := load()
		if err != nil {
			panic("obscura/bpe: " + err.Error())
		}
		shared = enc
	})
	return shared
}

// CountTokens returns the number of BPE tokens s encodes to. An empty string is zero tokens.
func (e *Encoder) CountTokens(s string) int {
	if s == "" {
		return 0
	}

	// Each input byte starts as one symbol via the reversible byte->unicode mapping.
	symbols := make([]string, len(s))
	for i := 0; i < len(s); i++ {
		symbols[i] = string(e.byteToRune[s[i]])
	}

	// Repeatedly merge the adjacent pair with the lowest rank until none remain mergeable.
	for len(symbols) >= 2 {
		minRank := int(^uint(0) >> 1)
		minIdx := -1
		for i := 0; i < len(symbols)-1; i++ {
			if r, ok := e.ranks[symbols[i]+pairSep+symbols[i+1]]; ok && r < minRank {
				minRank = r
				minIdx = i
			}
		}
		if minIdx < 0 {
			break
		}
		symbols[minIdx] += symbols[minIdx+1]
		symbols = append(symbols[:minIdx+1], symbols[minIdx+2:]...)
	}
	return len(symbols)
}

// load decodes the embedded, gzipped GPT-2 merge list into an Encoder.
func load() (*Encoder, error) {
	gz, err := gzip.NewReader(bytes.NewReader(mergesGz))
	if err != nil {
		return nil, err
	}
	defer gz.Close()

	ranks := make(map[string]int, 50000)
	sc := bufio.NewScanner(gz)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	rank := 0
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue // skip the "#version" header and any blank lines
		}
		left, right, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}
		ranks[left+pairSep+right] = rank
		rank++
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}

	return &Encoder{ranks: ranks, byteToRune: byteToUnicode()}, nil
}

// byteToUnicode builds GPT-2's reversible mapping from all 256 byte values to printable
// unicode code points, so every byte is representable as a distinct symbol.
func byteToUnicode() [256]rune {
	var table [256]rune
	var assigned [256]bool

	// Printable ASCII and Latin-1 ranges map to themselves.
	ranges := [][2]int{{'!', '~'}, {0xA1, 0xAC}, {0xAE, 0xFF}}
	for _, rg := range ranges {
		for b := rg[0]; b <= rg[1]; b++ {
			table[b] = rune(b)
			assigned[b] = true
		}
	}
	// Remaining bytes map to code points starting at 256, in byte order.
	n := 0
	for b := range 256 {
		if assigned[b] {
			continue
		}
		table[b] = rune(256 + n)
		n++
	}
	return table
}

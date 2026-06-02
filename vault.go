package obscura

import (
	"log/slog"
	"strings"
	"unicode/utf8"
)

// Vault maps placeholders to the originals they replaced during a single Redact call. It is
// populated by one goroutine inside Redact; once Redact returns it is read-only and therefore
// safe for concurrent Restore calls.
//
// A Vault holds plaintext secrets in memory, so it implements slog.LogValuer to keep those
// values out of logs: logging a Vault yields only an entry count.
type Vault struct {
	style    PlaceholderStyle
	byPlace  map[string]entry           // placeholder -> original + kind
	byValue  map[Kind]map[string]string // kind -> value -> placeholder (stable dedupe)
	counters map[Kind]int               // per-kind running index
}

// entry is a single vaulted original together with the kind it was detected as.
type entry struct {
	original string
	kind     Kind
}

// RestoreStreamer restores placeholders in a token/SSE stream where a single placeholder may
// be split across delta boundaries (and the multi-byte Unicode delimiter may itself split).
// It is stateful and single-consumer: not safe for concurrent use.
type RestoreStreamer struct {
	v     *Vault
	open  string
	carry []byte // buffered tail that may contain an in-flight placeholder or partial rune.
}

// newVault builds an empty Vault for the given placeholder style.
func newVault(style PlaceholderStyle) *Vault {
	return &Vault{
		style:    style,
		byPlace:  make(map[string]entry, 8),
		byValue:  make(map[Kind]map[string]string, 8),
		counters: make(map[Kind]int, 8),
	}
}

// Restore swaps every placeholder in llmOutput back to its original value in a single pass.
// Placeholders are collision-proof against normal text, so this is exact.
func (v *Vault) Restore(llmOutput string) string {
	if len(v.byPlace) == 0 {
		return llmOutput
	}
	pairs := make([]string, 0, len(v.byPlace)*2)
	for ph, e := range v.byPlace {
		pairs = append(pairs, ph, e.original)
	}
	return strings.NewReplacer(pairs...).Replace(llmOutput)
}

// NewRestoreStreamer returns a stateful restorer for streamed model output. Feed each delta to
// Push and call Flush once at end of stream.
func (v *Vault) NewRestoreStreamer() *RestoreStreamer {
	return &RestoreStreamer{v: v, open: v.style.Open()}
}

// Len reports the number of distinct values held in the vault. Useful for metrics.
func (v *Vault) Len() int { return len(v.byPlace) }

// LogValue implements slog.LogValuer so a Vault never leaks its contents to logs.
func (v *Vault) LogValue() slog.Value {
	return slog.GroupValue(slog.Int("entries", len(v.byPlace)))
}

// Push consumes a stream delta and returns the portion now safe to emit, with all complete
// placeholders restored. A trailing fragment that might still be an arriving placeholder is
// buffered until a later Push or Flush completes it.
func (s *RestoreStreamer) Push(delta string) string {
	s.carry = append(s.carry, delta...)
	cut := s.safeEmitBoundary()
	if cut == 0 {
		return ""
	}
	out := s.v.Restore(string(s.carry[:cut]))
	s.carry = append(s.carry[:0], s.carry[cut:]...)
	return out
}

// Flush emits everything still buffered at end of stream, restoring any complete placeholders.
// An unterminated placeholder is emitted literally — it was never a real one.
func (s *RestoreStreamer) Flush() string {
	if len(s.carry) == 0 {
		return ""
	}
	out := s.v.Restore(string(s.carry))
	s.carry = s.carry[:0]
	return out
}

// placeholderFor returns the placeholder for a (kind, value) pair, allocating a new stable
// one on first sight and reusing it on repeats so identical values map to identical tokens.
func (v *Vault) placeholderFor(kind Kind, value string) string {
	if byVal, ok := v.byValue[kind]; ok {
		if ph, ok := byVal[value]; ok {
			return ph
		}
	}
	v.counters[kind]++
	ph := v.style.Format(kind, v.counters[kind])

	byVal, ok := v.byValue[kind]
	if !ok {
		byVal = make(map[string]string, 4)
		v.byValue[kind] = byVal
	}
	byVal[value] = ph
	v.byPlace[ph] = entry{original: value, kind: kind}
	return ph
}

// safeEmitBoundary returns the byte offset up to which the carry buffer is safe to emit. It
// holds back from the last unclosed opening delimiter (a placeholder may still be arriving)
// and, failing that, from any incomplete trailing UTF-8 sequence (the delimiter itself can be
// split across deltas).
func (s *RestoreStreamer) safeEmitBoundary() int {
	// Hold back from the last opening delimiter that has no closing delimiter after it.
	if idx := s.lastUnclosedOpen(); idx >= 0 {
		return idx
	}
	// No in-flight placeholder: emit everything up to the last complete rune.
	return trimPartialRune(s.carry)
}

// lastUnclosedOpen finds the byte index of the last opening delimiter in carry that is not
// followed by a matching closing delimiter, or -1 if every opener is already closed. It also
// accounts for an opening delimiter that is only partially present at the very end.
func (s *RestoreStreamer) lastUnclosedOpen() int {
	carry := string(s.carry)
	closeDelim := s.v.style.Close()
	search := carry
	for {
		idx := strings.LastIndex(search, s.open)
		if idx < 0 {
			break
		}
		// Is there a closing delimiter somewhere after this opener?
		if !strings.Contains(carry[idx+len(s.open):], closeDelim) {
			return idx
		}
		// This opener is closed; keep looking further left.
		search = search[:idx]
	}
	// The opener may be only partially present at the tail (e.g. first byte of a 3-byte rune).
	if p := partialOpenSuffix(carry, s.open); p >= 0 {
		return p
	}
	return len(s.carry)
}

// trimPartialRune returns the length of b minus any incomplete multi-byte UTF-8 sequence at
// its end, so callers never emit half a rune.
func trimPartialRune(b []byte) int {
	if len(b) == 0 {
		return 0
	}
	// Walk back over continuation bytes (10xxxxxx) to find the last rune start.
	for i := len(b) - 1; i >= 0 && i >= len(b)-utf8.UTFMax; i-- {
		if b[i]&0xC0 == 0x80 {
			continue // continuation byte
		}
		if utf8.RuneStart(b[i]) {
			if r, size := utf8.DecodeRune(b[i:]); r != utf8.RuneError || size > 1 {
				return len(b) // last rune is complete
			}
			return i // incomplete rune begins at i
		}
	}
	return len(b)
}

// partialOpenSuffix reports the index at which a proper, non-empty prefix of open appears as a
// suffix of s (meaning the opening delimiter may still be arriving), or -1 if none does.
func partialOpenSuffix(s, open string) int {
	maxLen := min(len(open)-1, len(s))
	for n := maxLen; n >= 1; n-- {
		if strings.HasSuffix(s, open[:n]) {
			return len(s) - n
		}
	}
	return -1
}

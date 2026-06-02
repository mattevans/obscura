package obscura

import (
	"regexp"
	"strconv"
)

// PlaceholderStyle formats and parses the tokens that stand in for redacted values. A style
// must be a bijection over (Kind, index): Format produces a token, Parse recovers the pair,
// and tokens must survive a round-trip through an LLM verbatim.
type PlaceholderStyle interface {
	// Format renders the placeholder for the n-th value of a kind (n is 1-based).
	Format(kind Kind, n int) string
	// Parse reports whether s is a placeholder of this style and, if so, its kind and index.
	Parse(s string) (kind Kind, n int, ok bool)
	// Open returns the opening delimiter, used by the streaming restorer to find token starts.
	Open() string
	// Close returns the closing delimiter, used by the streaming restorer to find token ends.
	Close() string
}

// delimStyle is the shared implementation for the bracketed styles (Unicode and ASCII). Both
// render as <open><KIND>_<n><close> and differ only in their delimiters.
type delimStyle struct {
	open  string
	close string
	re    *regexp.Regexp
}

// StyleUnicode is the default style: ⟦EMAIL_1⟧ (U+27E6 / U+27E7 mathematical brackets). These
// code points effectively never occur in user text or model output, making restore exact.
func StyleUnicode() PlaceholderStyle { return newDelimStyle("⟦", "⟧") }

// StyleASCII renders [[EMAIL_1]] — the safe fallback for models that mangle exotic Unicode.
func StyleASCII() PlaceholderStyle { return newDelimStyle("[[", "]]") }

// StyleCustom builds a style from arbitrary delimiters (e.g. "<<" and ">>"). The delimiters
// must not be empty and should be improbable in normal text.
func StyleCustom(open, closing string) PlaceholderStyle { return newDelimStyle(open, closing) }

func newDelimStyle(open, closing string) PlaceholderStyle {
	// Match <open>KIND_n<close> where KIND is upper-case letters/underscores and n is digits.
	re := regexp.MustCompile("^" + regexp.QuoteMeta(open) + `([A-Z_]+)_(\d+)` + regexp.QuoteMeta(closing) + "$")

	return &delimStyle{open: open, close: closing, re: re}
}

// Format renders the placeholder for the n-th value of a kind.
func (d *delimStyle) Format(kind Kind, n int) string {
	return d.open + string(kind) + "_" + strconv.Itoa(n) + d.close
}

// Parse recovers the kind and index from a placeholder, or reports ok=false.
func (d *delimStyle) Parse(s string) (Kind, int, bool) {
	m := d.re.FindStringSubmatch(s)
	if m == nil {
		return "", 0, false
	}

	n, err := strconv.Atoi(m[2])
	if err != nil {
		return "", 0, false
	}

	return Kind(m[1]), n, true
}

// Open returns the opening delimiter.
func (d *delimStyle) Open() string { return d.open }

// Close returns the closing delimiter.
func (d *delimStyle) Close() string { return d.close }

// Package corpus is obscura's internal accuracy harness: a labelled fixture corpus, an
// inline-marker parser, and a precision/recall scorer. It backs the CI regression gate in
// accuracy_test.go and the published accuracy numbers in the README.
//
// Fixtures are authored with inline markers so gold spans never carry hand-computed byte
// offsets. A span is opened with "<<KIND>>" and closed with "<<>>":
//
//	Email <<EMAIL>>jane@example.com<<>> about your order.
//
// Parse strips the markers, yielding the clean text plus gold Spans whose offsets are computed
// from the stripped text. Documents with no markers are hard negatives: any match against them
// is a false positive.
package corpus

import (
	"embed"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"

	"github.com/mattevans/obscura"
)

//go:embed testdata/*.txt
var files embed.FS

const (
	markerOpen  = "<<"
	markerClose = ">>"
)

// Span is a labelled region of a document: a Kind and a half-open [Start, End) byte range into
// the document's clean (marker-stripped) text, with Value the substring it covers.
type Span struct {
	Kind  obscura.Kind
	Start int
	End   int
	Value string
}

// Doc is one labelled fixture: a name, the clean text a detector sees, and the gold Spans it is
// expected to find. A Doc with no Spans is a hard negative.
type Doc struct {
	Name  string
	Text  string
	Spans []Span
}

// Load parses every embedded fixture file into a Doc, sorted by name for deterministic
// iteration. Each file is one document; its base name (without extension) names the Doc.
func Load() ([]Doc, error) {
	entries, err := fs.ReadDir(files, "testdata")
	if err != nil {
		return nil, fmt.Errorf("corpus: read testdata: %w", err)
	}

	docs := make([]Doc, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".txt") {
			continue
		}

		raw, err := fs.ReadFile(files, path.Join("testdata", e.Name()))
		if err != nil {
			return nil, fmt.Errorf("corpus: read %s: %w", e.Name(), err)
		}

		name := strings.TrimSuffix(e.Name(), ".txt")

		doc, err := Parse(name, string(raw))
		if err != nil {
			return nil, fmt.Errorf("corpus: parse %s: %w", e.Name(), err)
		}

		docs = append(docs, doc)
	}

	sort.Slice(docs, func(i, j int) bool { return docs[i].Name < docs[j].Name })

	return docs, nil
}

// Parse strips inline markers from marked, returning a Doc whose Text is the clean string and
// whose Spans carry offsets into that clean text. Markers may nest; an unbalanced or malformed
// marker is an error.
func Parse(name, marked string) (Doc, error) {
	var b strings.Builder
	b.Grow(len(marked))

	type open struct {
		kind  obscura.Kind
		start int
	}

	stack := make([]open, 0, 4)
	spans := make([]Span, 0, 8)

	i := 0
	for i < len(marked) {
		if strings.HasPrefix(marked[i:], markerOpen) {
			rel := strings.Index(marked[i+len(markerOpen):], markerClose)
			if rel < 0 {
				return Doc{}, fmt.Errorf("corpus: %s: unterminated marker at byte %d", name, i)
			}

			token := marked[i+len(markerOpen) : i+len(markerOpen)+rel]
			i += len(markerOpen) + rel + len(markerClose)

			if token == "" { // close marker "<<>>"
				if len(stack) == 0 {
					return Doc{}, fmt.Errorf("corpus: %s: close marker with no open at byte %d", name, i)
				}

				o := stack[len(stack)-1]
				stack = stack[:len(stack)-1]

				spans = append(spans, Span{Kind: o.kind, Start: o.start, End: b.Len()})

				continue
			}

			stack = append(stack, open{kind: obscura.Kind(token), start: b.Len()})

			continue
		}

		b.WriteByte(marked[i])
		i++
	}

	if len(stack) > 0 {
		return Doc{}, fmt.Errorf("corpus: %s: %d unclosed marker(s)", name, len(stack))
	}

	text := b.String()
	for j := range spans {
		spans[j].Value = text[spans[j].Start:spans[j].End]
	}

	sort.Slice(spans, func(a, c int) bool { return spans[a].Start < spans[c].Start })

	return Doc{Name: name, Text: text, Spans: spans}, nil
}

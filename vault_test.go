package obscura_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mattevans/obscura"
	"github.com/mattevans/obscura/pii"
)

func TestRestoreStreamerMatchesOneShot(t *testing.T) {
	styles := map[string]obscura.PlaceholderStyle{
		"unicode": obscura.StyleUnicode(),
		"ascii":   obscura.StyleASCII(),
	}

	for name, style := range styles {
		t.Run(name, func(t *testing.T) {
			s := obscura.New(
				obscura.WithDetectors(pii.All()...),
				obscura.WithPlaceholderStyle(style),
			)
			clean, vault := s.Redact("email a@b.com and card 4111 1111 1111 1111 ok")
			require.NotEqual(t, 0, vault.Len())

			// The model "echoes" the cleaned text. Restoring it whole is our reference.
			want := vault.Restore(clean)

			// Split the cleaned text at every byte offset and feed the two halves as a stream;
			// the streamer must reproduce the one-shot result regardless of where the cut lands
			// (including mid-placeholder and mid-rune for the Unicode delimiter).
			for i := 0; i <= len(clean); i++ {
				st := vault.NewRestoreStreamer()

				var got strings.Builder
				got.WriteString(st.Push(clean[:i]))
				got.WriteString(st.Push(clean[i:]))
				got.WriteString(st.Flush())
				assert.Equal(t, want, got.String(), "split at byte %d", i)
			}
		})
	}
}

func TestRestoreStreamerByteByByte(t *testing.T) {
	s := obscura.New(obscura.WithDetectors(pii.All()...))
	clean, vault := s.Redact("contact a@b.com or c@d.org now")
	want := vault.Restore(clean)

	st := vault.NewRestoreStreamer()

	var got strings.Builder
	for i := 0; i < len(clean); i++ {
		got.WriteString(st.Push(clean[i : i+1]))
	}

	got.WriteString(st.Flush())
	assert.Equal(t, want, got.String())
}

func TestRestoreStreamerUnterminatedPlaceholderEmittedLiterally(t *testing.T) {
	_, vault := obscura.New(obscura.WithDetectors(pii.All()...)).Redact("a@b.com")
	st := vault.NewRestoreStreamer()
	// A lone opening delimiter that never closes is not a real placeholder.
	out := st.Push("text with ⟦EMA")
	out += st.Flush()
	assert.Equal(t, "text with ⟦EMA", out)
}

func TestVaultLogValueHidesContents(t *testing.T) {
	_, vault := obscura.New(obscura.WithDetectors(pii.All()...)).Redact("a@b.com x@y.com")
	v := vault.LogValue()
	rendered := v.String()
	assert.NotContains(t, rendered, "a@b.com")
	assert.Contains(t, rendered, "entries")
}

func TestRestoreEmptyVaultIsIdentity(t *testing.T) {
	_, vault := obscura.New().Redact("nothing here")
	assert.Equal(t, "hello world", vault.Restore("hello world"))
}

// FuzzStreamingRestore asserts that for any split point, the streamer reproduces the one-shot
// Restore of the cleaned text.
func FuzzStreamingRestore(f *testing.F) {
	f.Add("email a@b.com", 5)
	f.Add("a@b.com and c@d.com", 10)
	f.Add("card 4111 1111 1111 1111", 3)

	s := obscura.New(obscura.WithDetectors(pii.All()...))

	f.Fuzz(func(t *testing.T, input string, cut int) {
		clean, vault := s.Redact(input)
		want := vault.Restore(clean)

		if len(clean) == 0 {
			cut = 0
		} else {
			cut %= len(clean) + 1
			if cut < 0 {
				cut += len(clean) + 1
			}
		}

		st := vault.NewRestoreStreamer()

		var got strings.Builder
		got.WriteString(st.Push(clean[:cut]))
		got.WriteString(st.Push(clean[cut:]))
		got.WriteString(st.Flush())
		require.Equal(t, want, got.String())
	})
}

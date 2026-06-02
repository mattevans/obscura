package obscura_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/mattevans/obscura"
)

func TestPlaceholderStyleRoundTrip(t *testing.T) {
	styles := map[string]obscura.PlaceholderStyle{
		"unicode": obscura.StyleUnicode(),
		"ascii":   obscura.StyleASCII(),
		"custom":  obscura.StyleCustom("<<", ">>"),
	}
	for name, style := range styles {
		t.Run(name, func(t *testing.T) {
			s := style.Format(obscura.KindCreditCard, 7)
			kind, n, ok := style.Parse(s)
			assert.True(t, ok)
			assert.Equal(t, obscura.KindCreditCard, kind)
			assert.Equal(t, 7, n)
		})
	}
}

func TestPlaceholderParseRejectsNonPlaceholder(t *testing.T) {
	style := obscura.StyleUnicode()
	_, _, ok := style.Parse("just some text")
	assert.False(t, ok)
	_, _, ok = style.Parse("⟦EMAIL⟧") // missing index
	assert.False(t, ok)
}

func TestPlaceholderFormat(t *testing.T) {
	assert.Equal(t, "⟦EMAIL_1⟧", obscura.StyleUnicode().Format(obscura.KindEmail, 1))
	assert.Equal(t, "[[PHONE_3]]", obscura.StyleASCII().Format(obscura.KindPhone, 3))
}

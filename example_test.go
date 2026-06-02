package obscura_test

import (
	"fmt"

	"github.com/mattevans/obscura"
	"github.com/mattevans/obscura/pii"
)

// Redact replaces sensitive spans with stable placeholders and returns a Vault that reverses
// them, so a model's reply can be rehydrated to the originals.
func ExampleScrubber_Redact() {
	s := obscura.New(obscura.WithDetectors(pii.All()...))

	clean, vault := s.Redact("Email jane@example.com about invoice 4012 8888 8888 1881.")
	fmt.Println(clean)

	// A model echoes the placeholder back; Restore brings the original value with it.
	modelReply := "I'll email ⟦EMAIL_1⟧ now."
	fmt.Println(vault.Restore(modelReply))

	// Output:
	// Email ⟦EMAIL_1⟧ about invoice ⟦CREDIT_CARD_1⟧.
	// I'll email jane@example.com now.
}

// Within one call the same value always maps to the same placeholder, so the model sees a
// consistent entity and restoration is unambiguous.
func ExampleScrubber_Redact_stablePlaceholders() {
	s := obscura.New(obscura.WithDetectors(pii.All()...))

	clean, _ := s.Redact("from a@x.com to b@x.com, cc a@x.com")
	fmt.Println(clean)
	// Output:
	// from ⟦EMAIL_1⟧ to ⟦EMAIL_2⟧, cc ⟦EMAIL_1⟧
}

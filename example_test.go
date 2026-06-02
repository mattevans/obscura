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

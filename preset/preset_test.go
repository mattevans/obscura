package preset_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/mattevans/obscura"
	"github.com/mattevans/obscura/preset"
)

func TestPCIRedactsCard(t *testing.T) {
	s := obscura.New(preset.PCI()...)
	clean, vault := s.Redact("card 4111 1111 1111 1111")
	assert.Contains(t, clean, "CREDIT_CARD_1")
	assert.Equal(t, "card 4111 1111 1111 1111", vault.Restore(clean))
}

func TestGDPRRedactsContactAndSecret(t *testing.T) {
	s := obscura.New(preset.GDPR()...)
	clean, _ := s.Redact("email a@b.com key AKIAIOSFODNN7EXAMPLE")
	assert.Contains(t, clean, "EMAIL_1")
	assert.Contains(t, clean, "SECRET_1")
}

func TestHIPAARedactsIdentifiers(t *testing.T) {
	s := obscura.New(preset.HIPAA()...)
	clean, _ := s.Redact("patient ssn 123-45-6789 at 10.0.0.5")
	assert.Contains(t, clean, "GOV_ID_1")
	assert.Contains(t, clean, "IP_1")
}

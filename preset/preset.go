// Package preset provides curated obscura option bundles for common compliance regimes. Each
// returns a slice of obscura.Option, so a Scrubber is configured in one line:
//
//	s := obscura.New(preset.PCI()...)
//
// Presets are a starting point, not legal advice: review and extend them for your own data and
// obligations.
package preset

import (
	"github.com/mattevans/obscura"
	"github.com/mattevans/obscura/pii"
	"github.com/mattevans/obscura/secret"
	"github.com/mattevans/obscura/secret/tokenfilter"
)

// GDPR bundles detectors for personal data: contact details, identifiers, network and bank
// information, plus secrets. Names and addresses require the optional NER tier and are not
// included here.
func GDPR() []obscura.Option {
	return []obscura.Option{
		obscura.WithDetectors(
			pii.NewEmail(),
			pii.NewPhone(),
			pii.NewGovID(),
			pii.NewBusinessID(),
			pii.NewBank(),
			pii.NewNetwork(),
			pii.NewCrypto(),
		),
		obscura.WithDetector(secret.NewDetector(secret.DefaultRules())),
		obscura.WithFilter(tokenfilter.New()),
	}
}

// HIPAA bundles detectors relevant to protected health information identifiers handled in text:
// contact details, government IDs, and network identifiers. Free-text clinical names need the
// optional NER tier.
func HIPAA() []obscura.Option {
	return []obscura.Option{
		obscura.WithDetectors(
			pii.NewEmail(),
			pii.NewPhone(),
			pii.NewGovID(),
			pii.NewNetwork(),
		),
	}
}

// PCI bundles detectors for payment data: card numbers (Luhn-validated) and bank identifiers.
func PCI() []obscura.Option {
	return []obscura.Option{
		obscura.WithDetectors(
			pii.NewCreditCard(),
			pii.NewBank(),
		),
	}
}

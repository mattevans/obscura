package pii_test

import (
	"fmt"

	"github.com/mattevans/obscura"
	"github.com/mattevans/obscura/pii"
)

// ExampleWithLocales narrows detection to a set of jurisdictions. Here only US identifiers are
// recognised, so the US Social Security Number is redacted while the Australian Tax File Number is
// left untouched. Called with no locales, every supported jurisdiction is active.
func ExampleWithLocales() {
	s := obscura.New(obscura.WithDetectors(pii.All(pii.WithLocales(pii.LocaleUS))...))

	clean, _ := s.Redact("ssn 536-90-4399 and tfn 123 456 782")
	fmt.Println(clean)
	// Output:
	// ssn ⟦GOV_ID_1⟧ and tfn 123 456 782
}

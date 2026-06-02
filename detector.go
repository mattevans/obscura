package obscura

import "context"

// Kind identifies a category of sensitive content. Its stable string value doubles as the
// placeholder type token (e.g. KindEmail -> "⟦EMAIL_1⟧").
type Kind string

// Kinds of sensitive content obscura can detect. Values are stable: they appear in
// placeholders and audit rule ids, so changing them is a breaking change.
const (
	KindEmail      Kind = "EMAIL"
	KindPhone      Kind = "PHONE"
	KindCreditCard Kind = "CREDIT_CARD"
	KindIBAN       Kind = "IBAN"
	KindRouting    Kind = "ROUTING"
	KindIPAddress  Kind = "IP"
	KindMAC        Kind = "MAC"
	KindGovID      Kind = "GOV_ID"
	KindBusinessID Kind = "BUSINESS_ID"
	KindCrypto     Kind = "CRYPTO_ADDR"
	KindSecret     Kind = "SECRET"
	KindPerson     Kind = "PERSON"   // NER tier only
	KindLocation   Kind = "LOCATION" // NER tier only
	KindInjection  Kind = "INJECTION"
)

// Match is a single detected span of sensitive content. Start and End are byte offsets into
// the input string, half-open [Start, End); Value is that substring.
type Match struct {
	Kind  Kind
	Start int
	End   int
	Value string
	Score float64 // 0..1 confidence; callers may threshold per use case.
	Rule  string  // detector/rule id for audit, e.g. "pii:email" or "secret:aws-access-key".
}

// Detector finds spans of sensitive text. Pure-Go regex detectors ship built-in; ML/NER
// detectors are supplied by the caller behind this same interface.
//
// Detect MUST be pure, CPU-only and safe for concurrent use.
type Detector interface {
	Name() string
	Detect(text string) []Match
}

// ContextDetector is for detectors that do I/O or can block (remote NER, an LLM judge).
// Anything that blocks takes a context as its first parameter.
type ContextDetector interface {
	Name() string
	DetectContext(ctx context.Context, text string) ([]Match, error)
}

// filterProvider is an optional interface a Detector may implement to declare the validation
// filters it expects to run against its matches (e.g. a credit-card detector asks for Luhn).
// The Scrubber merges these into its filter chain when the detector is registered.
type filterProvider interface {
	DefaultFilters() []Filter
}

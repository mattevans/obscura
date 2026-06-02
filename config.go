package obscura

// defaultMinScore is the confidence floor a match must clear to be redacted unless overridden.
const defaultMinScore = 0.5

// Option configures a Scrubber at construction time. Options are applied in order.
type Option func(*config)

// config accumulates Scrubber settings while options are applied; it is assembled into the
// immutable Scrubber by New.
type config struct {
	detectors []Detector
	ctxDet    []ContextDetector
	filters   []Filter
	allow     []string
	deny      []string
	minScore  float64
	style     PlaceholderStyle
	priority  map[Kind]int
}

// policy holds the immutable decision parameters of a built Scrubber.
type policy struct {
	minScore float64
	style    PlaceholderStyle
	priority map[Kind]int
}

// WithDetector registers a single detector (built-in, secret, or a caller-supplied NER model).
func WithDetector(d Detector) Option {
	return func(c *config) { c.detectors = append(c.detectors, d) }
}

// WithDetectors registers several detectors at once, e.g. obscura.WithDetectors(pii.All()...).
func WithDetectors(ds ...Detector) Option {
	return func(c *config) { c.detectors = append(c.detectors, ds...) }
}

// WithContextDetector registers a detector that does I/O and runs under a context (NER, judge).
func WithContextDetector(d ContextDetector) Option {
	return func(c *config) { c.ctxDet = append(c.ctxDet, d) }
}

// WithFilter appends a global filter applied to every match after detector-default filters,
// e.g. obscura.WithFilter(tokenfilter.New()).
func WithFilter(f Filter) Option {
	return func(c *config) { c.filters = append(c.filters, f) }
}

// WithAllowlist marks values that must never be redacted even if a detector matches them.
func WithAllowlist(values ...string) Option {
	return func(c *config) { c.allow = append(c.allow, values...) }
}

// WithDenylist marks values that must always be redacted at maximum confidence.
func WithDenylist(values ...string) Option {
	return func(c *config) { c.deny = append(c.deny, values...) }
}

// WithMinScore sets the confidence threshold below which matches are discarded.
func WithMinScore(threshold float64) Option {
	return func(c *config) { c.minScore = threshold }
}

// WithPlaceholderStyle overrides the default Unicode placeholder style.
func WithPlaceholderStyle(s PlaceholderStyle) Option {
	return func(c *config) { c.style = s }
}

// WithKindPriority sets the overlap tie-break ordering, highest priority first. Kinds omitted
// here keep their default priority (which is lower than any kind named).
func WithKindPriority(order ...Kind) Option {
	return func(c *config) {
		c.priority = make(map[Kind]int, len(order))
		for i, k := range order {
			c.priority[k] = len(order) - i
		}
	}
}

// defaultPriority ranks kinds for overlap resolution: specific, checksum-validated kinds beat
// generic or loosely-structured ones when spans collide.
func defaultPriority() map[Kind]int {
	return map[Kind]int{
		KindCreditCard: 100,
		KindIBAN:       95,
		KindRouting:    90,
		KindBusinessID: 88,
		KindCrypto:     85,
		KindSecret:     80,
		KindEmail:      70,
		// GovID outranks Phone so a checksum-validated national ID (e.g. an AU TFN written as
		// three spaced groups) is not shadowed by the deliberately loose phone matcher.
		KindGovID: 65,
		// IPAddress and MAC outrank Phone: an octet-validated dotted-quad (e.g. 255.255.255.0)
		// or a hardware address is far more specific than the loose grouped-phone pattern, which
		// would otherwise clip the first three octets of an IP as a phone number.
		KindIPAddress: 63,
		KindMAC:       62,
		KindPhone:     60,
		KindInjection: 30,
		KindPerson:    20,
		KindLocation:  15,
	}
}

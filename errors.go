package obscura

import "errors"

// ErrNoDetectors is returned (or logged) when a Scrubber is built with no detectors. Such a
// Scrubber is legal — it passes text through unchanged — but the condition is usually a
// configuration mistake worth surfacing.
var ErrNoDetectors = errors.New("obscura: scrubber has no detectors configured")

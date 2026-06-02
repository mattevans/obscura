package obscura

// Session redacts several pieces of text into a single shared Vault. A value that appears in
// more than one piece (e.g. the same email across several JSON fields of one request) receives
// the same placeholder, and a single Restore call reverses them all.
//
// A Session is single-goroutine: build it, redact each field, then read the Vault. It is not
// safe for concurrent use; create one per request.
type Session struct {
	s *Scrubber
	v *Vault
}

// NewSession starts a redaction session backed by a fresh Vault.
func (s *Scrubber) NewSession() *Session {
	return &Session{s: s, v: newVault(s.policy.style)}
}

// Redact sanitizes text, recording originals in the session's shared Vault, and returns the
// cleaned text. It runs only synchronous Detectors.
func (sess *Session) Redact(text string) string {
	matches := sess.s.resolve(text, sess.s.detect(text))
	return sess.s.rewriteInto(text, matches, sess.v)
}

// Vault returns the shared Vault accumulating this session's redactions, for restoring
// responses once the session's requests have been made.
func (sess *Session) Vault() *Vault { return sess.v }

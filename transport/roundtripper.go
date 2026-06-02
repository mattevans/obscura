// Package transport provides a drop-in http.RoundTripper that redacts sensitive content from
// outbound request bodies and restores it in responses, so any LLM HTTP client can be made
// privacy-preserving by swapping its Transport. It is the flagship integration for AI gateways:
// integrate once and every downstream call is protected.
//
//	client := &http.Client{
//	    Transport: transport.New(scrubber, http.DefaultTransport,
//	        transport.JSONBodyFields("messages.*.content"),
//	        transport.RestoreResponse(true)),
//	}
//
// By default the transport fails closed: if a request body cannot be redacted it returns an
// error rather than forwarding un-redacted text. Use FailOpen to prefer availability instead.
package transport

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/mattevans/obscura"
)

// ErrRedactionFailed is returned (when failing closed) if an outbound body could not be
// redacted, e.g. it was not valid JSON.
var ErrRedactionFailed = errors.New("obscura/transport: outbound body redaction failed")

// Transport is an http.RoundTripper that redacts request bodies and restores responses.
type Transport struct {
	scrubber    *obscura.Scrubber
	base        http.RoundTripper
	fields      []fieldPath
	restoreResp bool
	failOpen    bool
}

// Option configures a Transport.
type Option func(*Transport)

// New wraps base with redaction driven by scrubber. If base is nil, http.DefaultTransport is
// used. Without any JSONBodyFields, request bodies are forwarded unchanged (response
// restoration still applies if enabled, though without redactions there is nothing to restore).
func New(scrubber *obscura.Scrubber, base http.RoundTripper, opts ...Option) *Transport {
	if base == nil {
		base = http.DefaultTransport
	}
	t := &Transport{scrubber: scrubber, base: base}
	for _, opt := range opts {
		opt(t)
	}
	return t
}

// JSONBodyFields targets the dotted JSON paths whose string values should be redacted, e.g.
// "messages.*.content" or "input". "*" matches every array element or object value.
func JSONBodyFields(paths ...string) Option {
	return func(t *Transport) { t.fields = append(t.fields, parseFieldPaths(paths)...) }
}

// RestoreResponse controls whether placeholders in the response body are restored to their
// originals. It handles both whole-body and streamed (SSE) responses.
func RestoreResponse(on bool) Option {
	return func(t *Transport) { t.restoreResp = on }
}

// FailOpen makes the transport forward the original request body if redaction fails, preferring
// availability over the safer fail-closed default.
func FailOpen() Option {
	return func(t *Transport) { t.failOpen = true }
}

// RoundTrip redacts the outbound body, forwards the request, and restores the response. It does
// not mutate the caller's request: a clone carries the redacted body.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	outbound, vault, err := t.redactRequest(req)
	if err != nil {
		return nil, err
	}

	resp, err := t.base.RoundTrip(outbound)
	if err != nil {
		return nil, err
	}

	if t.restoreResp && vault != nil && vault.Len() > 0 && resp.Body != nil {
		resp.Body = newRestoreReader(resp.Body, vault)
		resp.ContentLength = -1 // length changes after restoration; force chunked/unknown
		resp.Header.Del("Content-Length")
	}
	return resp, nil
}

// redactRequest returns a clone of req carrying the redacted body, plus the Vault of
// redactions. When there is no body or no fields to redact, it returns the request essentially
// unchanged and a nil Vault.
func (t *Transport) redactRequest(req *http.Request) (*http.Request, *obscura.Vault, error) {
	if req.Body == nil || len(t.fields) == 0 {
		return req, nil, nil
	}

	original, err := io.ReadAll(req.Body)
	_ = req.Body.Close()
	if err != nil {
		return nil, nil, fmt.Errorf("obscura/transport: reading request body: %w", err)
	}

	sess := t.scrubber.NewSession()
	redacted, err := redactJSONBody(original, t.fields, sess)
	if err != nil {
		if t.failOpen {
			return cloneWithBody(req, original), nil, nil
		}
		return nil, nil, fmt.Errorf("%w: %w", ErrRedactionFailed, err)
	}

	return cloneWithBody(req, redacted), sess.Vault(), nil
}

// cloneWithBody returns a shallow clone of req with its body replaced by the given bytes and
// the content length and GetBody updated to match, leaving the caller's request untouched.
func cloneWithBody(req *http.Request, body []byte) *http.Request {
	clone := req.Clone(req.Context())
	clone.Body = io.NopCloser(bytes.NewReader(body))
	clone.ContentLength = int64(len(body))
	clone.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}
	return clone
}

var _ http.RoundTripper = (*Transport)(nil)

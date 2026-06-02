package transport_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mattevans/obscura"
	"github.com/mattevans/obscura/pii"
	"github.com/mattevans/obscura/transport"
)

// roundTripFunc adapts a function to http.RoundTripper for use as a fake base transport.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// chunkReader yields its data in fixed-size pieces to exercise streaming restoration across
// read boundaries (e.g. a placeholder split mid-token).
type chunkReader struct {
	data []byte
	size int
	pos  int
}

func (c *chunkReader) Read(p []byte) (int, error) {
	if c.pos >= len(c.data) {
		return 0, io.EOF
	}

	end := min(c.pos+c.size, len(c.data))
	n := copy(p, c.data[c.pos:end])
	c.pos += n

	return n, nil
}

func (c *chunkReader) Close() error { return nil }

func newScrubber() *obscura.Scrubber {
	return obscura.New(obscura.WithDetectors(pii.All()...))
}

func jsonRequest(t *testing.T, body string) *http.Request {
	t.Helper()

	req, err := http.NewRequest(http.MethodPost, "https://api.example.com/v1/chat", strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	return req
}

func TestRedactsRequestBody(t *testing.T) {
	var outbound string

	base := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		b, _ := io.ReadAll(r.Body)
		outbound = string(b)

		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("{}")), Header: http.Header{}}, nil
	})

	rt := transport.New(newScrubber(), base, transport.JSONBodyFields("messages.*.content"))
	client := &http.Client{Transport: rt}

	resp, err := client.Do(jsonRequest(t, `{"messages":[{"role":"user","content":"email me at a@b.com"}]}`))
	require.NoError(t, err)

	defer resp.Body.Close()

	assert.NotContains(t, outbound, "a@b.com", "PII must not leave in the request body")
	assert.Contains(t, outbound, "EMAIL_1", "redacted body should carry a placeholder")
}

func TestRestoresResponseBody(t *testing.T) {
	base := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		// The model echoes the placeholder back in its reply.
		body := `{"reply":"Noted, I will email ⟦EMAIL_1⟧ shortly."}`

		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(body)),
			Header:     http.Header{},
		}, nil
	})

	rt := transport.New(newScrubber(), base,
		transport.JSONBodyFields("messages.*.content"),
		transport.RestoreResponse(true))
	client := &http.Client{Transport: rt}

	resp, err := client.Do(jsonRequest(t, `{"messages":[{"role":"user","content":"reach a@b.com"}]}`))
	require.NoError(t, err)

	defer resp.Body.Close()

	out, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Contains(t, string(out), "a@b.com", "response should be rehydrated")
	assert.NotContains(t, string(out), "EMAIL_1")
}

func TestRestoresStreamedResponseAcrossChunks(t *testing.T) {
	base := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		// SSE-style stream; the placeholder ⟦EMAIL_1⟧ will be split across 4-byte reads.
		body := "data: Noted ⟦EMAIL_1⟧\n\ndata: [DONE]\n\n"

		return &http.Response{
			StatusCode: 200,
			Body:       &chunkReader{data: []byte(body), size: 4},
			Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
		}, nil
	})

	rt := transport.New(newScrubber(), base,
		transport.JSONBodyFields("messages.*.content"),
		transport.RestoreResponse(true))
	client := &http.Client{Transport: rt}

	resp, err := client.Do(jsonRequest(t, `{"messages":[{"role":"user","content":"reach a@b.com"}]}`))
	require.NoError(t, err)

	defer resp.Body.Close()

	out, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Contains(t, string(out), "a@b.com", "split placeholder must still restore")
	assert.NotContains(t, string(out), "EMAIL_1")
}

func TestFailsClosedOnInvalidJSON(t *testing.T) {
	called := false
	base := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		called = true

		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("{}")), Header: http.Header{}}, nil
	})

	rt := transport.New(newScrubber(), base, transport.JSONBodyFields("content"))
	client := &http.Client{Transport: rt}

	resp, err := client.Do(jsonRequest(t, `not valid json at all`))
	require.Error(t, err)
	assert.ErrorIs(t, err, transport.ErrRedactionFailed)
	assert.False(t, called, "must not forward when redaction fails closed")

	if resp != nil {
		_ = resp.Body.Close()
	}
}

func TestFailOpenForwardsOriginal(t *testing.T) {
	var outbound string

	base := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		b, _ := io.ReadAll(r.Body)
		outbound = string(b)

		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("{}")), Header: http.Header{}}, nil
	})

	rt := transport.New(newScrubber(), base,
		transport.JSONBodyFields("content"),
		transport.FailOpen())
	client := &http.Client{Transport: rt}

	resp, err := client.Do(jsonRequest(t, `plain text body`))
	require.NoError(t, err)

	defer resp.Body.Close()

	assert.Equal(t, "plain text body", outbound, "fail-open forwards the original body")
}

func TestDoesNotMutateCallerRequestMetadata(t *testing.T) {
	// The forwarded request must be a clone: the redacted body is set on the clone, so the
	// caller's request keeps its original headers and URL. (Consuming Body is permitted by the
	// RoundTripper contract.)
	var forwarded *http.Request

	base := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		forwarded = r

		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("{}")), Header: http.Header{}}, nil
	})
	rt := transport.New(newScrubber(), base, transport.JSONBodyFields("messages.*.content"))

	req := jsonRequest(t, `{"messages":[{"role":"user","content":"a@b.com"}]}`)
	req.Header.Set("X-Caller", "keep-me")
	resp, err := rt.RoundTrip(req)
	require.NoError(t, err)

	defer resp.Body.Close()

	require.NotNil(t, forwarded)
	assert.NotSame(t, req, forwarded, "must forward a clone, not the caller's request")
	assert.Equal(t, "keep-me", forwarded.Header.Get("X-Caller"), "headers must be preserved on the clone")
	assert.Equal(t, req.URL.String(), forwarded.URL.String())
}

func TestNoBodyPassesThrough(t *testing.T) {
	base := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("ok")), Header: http.Header{}}, nil
	})
	rt := transport.New(newScrubber(), base, transport.JSONBodyFields("content"))

	req, err := http.NewRequest(http.MethodGet, "https://api.example.com/health", nil)
	require.NoError(t, err)
	resp, err := rt.RoundTrip(req)
	require.NoError(t, err)

	defer resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode)
}

func TestRedactedBodyIsValidJSON(t *testing.T) {
	var outbound []byte

	base := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		outbound, _ = io.ReadAll(r.Body)

		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("{}")), Header: http.Header{}}, nil
	})
	rt := transport.New(newScrubber(), base, transport.JSONBodyFields("messages.*.content"))

	resp, err := rt.RoundTrip(jsonRequest(t, `{"messages":[{"role":"user","content":"a@b.com and 4111 1111 1111 1111"}],"model":"x"}`))
	require.NoError(t, err)

	defer resp.Body.Close()

	var parsed map[string]any
	require.NoError(t, json.Unmarshal(outbound, &parsed), "redacted body must remain valid JSON")
	assert.Equal(t, "x", parsed["model"], "non-targeted fields must be preserved")

	_ = bytes.TrimSpace(outbound)
}

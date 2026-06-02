package transport

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"

	"github.com/mattevans/obscura"
)

// fieldPath is a parsed dotted JSON path such as "messages.*.content", where "*" matches every
// element of an array or every value of an object.
type fieldPath []string

// restoreReader wraps a response body, restoring placeholders in the byte stream as it is read.
// It works for both whole-body JSON and chunked SSE responses because placeholders are
// collision-proof: restoring them anywhere in the stream is correct. Trailing bytes that might
// be an in-flight placeholder are held back until more data arrives or EOF triggers a flush.
type restoreReader struct {
	src io.ReadCloser
	st  *obscura.RestoreStreamer
	buf bytes.Buffer
	eof bool
}

// parseFieldPaths splits dotted path strings into segment lists.
func parseFieldPaths(paths []string) []fieldPath {
	out := make([]fieldPath, 0, len(paths))
	for _, p := range paths {
		out = append(out, strings.Split(p, "."))
	}
	return out
}

// redactJSONBody parses body as JSON, redacts every configured field into one shared session
// (so identical values share a placeholder), and returns the re-marshaled body. All redactions
// land in sess.Vault for later response restoration.
func redactJSONBody(body []byte, paths []fieldPath, sess *obscura.Session) ([]byte, error) {
	var root any
	if err := json.Unmarshal(body, &root); err != nil {
		return nil, err
	}
	for _, p := range paths {
		root = redactPath(root, p, sess)
	}
	return json.Marshal(root)
}

// redactPath walks node along path, redacting string leaves through the session. Maps and
// slices are mutated in place; the (possibly replaced) node is returned so string leaves can be
// written back into their parent.
func redactPath(node any, path fieldPath, sess *obscura.Session) any {
	if len(path) == 0 {
		if str, ok := node.(string); ok {
			return sess.Redact(str)
		}
		return node
	}

	seg, rest := path[0], path[1:]
	switch n := node.(type) {
	case map[string]any:
		if seg == "*" {
			for k, v := range n {
				n[k] = redactPath(v, rest, sess)
			}
			return n
		}
		if v, ok := n[seg]; ok {
			n[seg] = redactPath(v, rest, sess)
		}
		return n
	case []any:
		if seg == "*" {
			for i, v := range n {
				n[i] = redactPath(v, rest, sess)
			}
		}
		return n
	default:
		return node
	}
}

// newRestoreReader wraps src so that reads return content with placeholders restored from v.
func newRestoreReader(src io.ReadCloser, v *obscura.Vault) *restoreReader {
	return &restoreReader{src: src, st: v.NewRestoreStreamer()}
}

// Read fills p with restored output, pulling and restoring more source bytes as needed.
func (r *restoreReader) Read(p []byte) (int, error) {
	for r.buf.Len() == 0 && !r.eof {
		chunk := make([]byte, 4096)
		n, err := r.src.Read(chunk)
		if n > 0 {
			r.buf.WriteString(r.st.Push(string(chunk[:n])))
		}
		switch {
		case err == io.EOF:
			r.buf.WriteString(r.st.Flush())
			r.eof = true
		case err != nil:
			return 0, err
		}
	}
	if r.buf.Len() == 0 && r.eof {
		return 0, io.EOF
	}
	return r.buf.Read(p)
}

// Close closes the underlying response body.
func (r *restoreReader) Close() error { return r.src.Close() }

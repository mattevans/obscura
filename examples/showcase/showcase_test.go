package main

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

var update = flag.Bool("update", false, "regenerate the golden showcase file")

// TestShowcaseGolden pins the showcase output so CI fails if detection behaviour drifts. When the
// change is intended, regenerate the file with: go test ./examples/showcase -update.
func TestShowcaseGolden(t *testing.T) {
	var buf bytes.Buffer

	if err := render(&buf); err != nil {
		t.Fatalf("render: %v", err)
	}

	golden := filepath.Join("testdata", "showcase.golden")

	if *update {
		if err := os.WriteFile(golden, buf.Bytes(), 0o600); err != nil {
			t.Fatalf("write golden: %v", err)
		}

		return
	}

	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden (run with -update to create it): %v", err)
	}

	if !bytes.Equal(buf.Bytes(), want) {
		t.Errorf("showcase output drifted from %s; run `go test ./examples/showcase -update` to refresh.\n--- got ---\n%s", golden, buf.String())
	}
}

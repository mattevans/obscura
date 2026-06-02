// Command openrouter is a small end-to-end smoke test for obscura against a real LLM.
//
// It sends a prompt containing fake-but-realistic PII to OpenRouter (an OpenAI-compatible API)
// through obscura's drop-in HTTP transport, and shows that:
//
//  1. obscura swaps the PII for placeholders before the request leaves the process,
//  2. only those placeholders reach OpenRouter, and
//  3. the originals are restored in the model's reply.
//
// Usage:
//
//	export OPENROUTER_API_KEY=sk-or-...   # never commit or paste this into a chat
//	go run ./examples/openrouter
//
// Optionally override the model (defaults to a cheap one):
//
//	MODEL=anthropic/claude-3.5-haiku go run ./examples/openrouter
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/mattevans/obscura"
	"github.com/mattevans/obscura/pii"
	"github.com/mattevans/obscura/secret"
	"github.com/mattevans/obscura/transport"
)

const (
	endpoint     = "https://openrouter.ai/api/v1/chat/completions"
	defaultModel = "openai/gpt-4o-mini"
)

func main() {
	apiKey := os.Getenv("OPENROUTER_API_KEY")
	if apiKey == "" {
		fmt.Fprintln(os.Stderr, "set OPENROUTER_API_KEY first (do not paste it into a chat)")
		os.Exit(1)
	}

	model := os.Getenv("MODEL")
	if model == "" {
		model = defaultModel
	}

	// A prompt carrying fake PII. We ask the model to echo it back so restoration is visible.
	// Note: the name "John Smith" is deliberately NOT redacted — free-form names are out of scope
	// for the regex core (that is the optional NER tier). The email, phone, and card are.
	prompt := "Repeat the following line back to me exactly, word for word, with no changes:\n" +
		"Contact John Smith at john.smith@example.com or +1 415 555 0132; card 4111 1111 1111 1111."

	// All built-in PII detectors plus the secret ruleset. ASCII placeholders ([[EMAIL_1]]) survive
	// a round-trip through an arbitrary model more reliably than the exotic Unicode default.
	scrubber := obscura.New(
		obscura.WithDetectors(pii.All()...),
		obscura.WithDetector(secret.NewDetector(secret.DefaultRules())),
		obscura.WithPlaceholderStyle(obscura.StyleASCII()),
	)

	// Preview locally what the model is about to see.
	clean, _ := scrubber.Redact(prompt)
	fmt.Printf("── you send ──\n%s\n\n── model sees (local preview) ──\n%s\n", prompt, clean)

	// Wrap the real transport: obscura redacts outbound and restores inbound, while the peek layer
	// underneath prints exactly what crosses the wire to OpenRouter.
	client := &http.Client{
		Timeout: 60 * time.Second,
		Transport: transport.New(scrubber, peek{next: http.DefaultTransport},
			transport.JSONBodyFields("messages.*.content"),
			transport.RestoreResponse(true)),
	}

	answer, err := chat(client, apiKey, model, prompt)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

	// This answer has already been rehydrated by obscura, so any placeholder the model echoed is
	// back to its original value.
	fmt.Printf("\n── you get back (restored) ──\n%s\n", answer)
}

// chat posts a single user message to the OpenRouter chat-completions endpoint and returns the
// assistant's reply text.
func chat(client *http.Client, apiKey, model, prompt string) (string, error) {
	reqBody, err := json.Marshal(map[string]any{
		"model": model,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
	})
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(reqBody))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("openrouter %s: %s", resp.Status, body)
	}

	var parsed struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", err
	}

	if len(parsed.Choices) == 0 {
		return "", fmt.Errorf("no choices in response: %s", body)
	}

	return parsed.Choices[0].Message.Content, nil
}

// peek is an http.RoundTripper that prints the outbound request body — exactly what OpenRouter
// receives, after obscura has redacted it — then forwards the request unchanged.
type peek struct {
	next http.RoundTripper
}

// RoundTrip prints the (already-redacted) request body, then delegates to the wrapped transport.
func (p peek) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Body != nil {
		b, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}

		req.Body = io.NopCloser(bytes.NewReader(b))

		fmt.Printf("\n── what actually reaches OpenRouter ──\n%s\n", b)
	}

	return p.next.RoundTrip(req)
}

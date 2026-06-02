# obscura

Detect and **reversibly redact** PII, secrets, and prompt-injection patterns from text
*before* it leaves your process for an LLM — then restore the originals in the model's
response.

```
user text ──▶ Redact ──▶ ⟦EMAIL_1⟧ … ──▶ LLM ──▶ "…⟦EMAIL_1⟧…" ──▶ Restore ──▶ original
                 │                                                        ▲
                 └────────────────────── Vault ──────────────────────────┘
```

obscura is a small, idiomatic, pure-Go library. The core has **no required third-party
dependencies**, embeds all its data (no runtime downloads, no telemetry), and is safe for
concurrent use.

## Why

The Go ecosystem has good secret *scanners* (gitleaks, betterleaks) and a long tail of
regex-only PII libraries — but nothing that combines **PII + secrets + injection** behind a
**reversible, streaming-safe** redaction workflow as an embeddable library. That workflow —
redact → call the model → rehydrate — is exactly what an AI gateway or any privacy-sensitive
backend needs, and it lived only inside closed SaaS proxies. obscura is that piece, open.

## Install

```sh
go get github.com/mattevans/obscura
```

Requires Go 1.23+.

## Quick start

```go
import (
    "github.com/mattevans/obscura"
    "github.com/mattevans/obscura/pii"
    "github.com/mattevans/obscura/secret"
    "github.com/mattevans/obscura/secret/tokenfilter"
)

s := obscura.New(
    obscura.WithDetectors(pii.All()...),
    obscura.WithDetector(secret.NewDetector(secret.DefaultRules())),
    obscura.WithFilter(tokenfilter.New()),          // BPE false-positive suppression
    obscura.WithAllowlist("support@acme.com"),
    obscura.WithMinScore(0.5),
)

clean, vault := s.Redact(userPrompt)   // the model only ever sees ⟦EMAIL_1⟧, ⟦SECRET_1⟧, …
resp := callLLM(clean)
final := vault.Restore(resp)           // originals reappear in the answer
```

The same value always maps to the same placeholder within a call, so the model sees a
consistent entity and restoration is unambiguous.

## Drop-in HTTP transport (the flagship integration)

Make any LLM HTTP client privacy-preserving by swapping its `Transport`. Outbound request
fields are redacted; responses — including streamed SSE — are restored automatically.

```go
client := &http.Client{
    Transport: transport.New(s, http.DefaultTransport,
        transport.JSONBodyFields("messages.*.content"),
        transport.RestoreResponse(true)),
}
```

The transport **fails closed** by default: if a body can't be redacted it returns an error
rather than forwarding un-redacted text. Use `transport.FailOpen()` to prefer availability.

## What it detects

| Package | Kinds | Validation |
|---|---|---|
| `pii` | email, phone, credit card, IBAN/ABA, IPv4/IPv6, MAC, SSN/NINO/TFN, ABN/NZBN, BTC/ETH | Luhn, IBAN mod-97, ABA/ABN/NZBN/TFN checksums, context cues |
| `secret` | AWS, GitHub/GitLab, Slack, Stripe, Google, OpenAI/Anthropic, JWT, private keys, generic assignments | Aho-Corasick keyword pre-filter, Shannon entropy, optional BPE token-efficiency |
| `injection` | instruction-override, prompt-exfiltration, role-play, jailbreak, chat-template delimiters | heuristic tripwire (defense-in-depth, not a guarantee) |

## The BPE token-efficiency filter

Entropy alone is blunt: some prose scores high, some real keys score modestly. A byte-level
BPE tokenizer learns its merges from English, so **natural language compresses efficiently
(~3.5–4 chars/token)** while **random secrets fragment (~1.5–2 chars/token)**. obscura ships a
tiny *count-only* BPE engine (embedding GPT-2's MIT merge ranks, ~200 KB gz) that uses this
ratio to drop natural-language false positives. It lives under `secret/tokenfilter`, so callers
who don't enable it never compile or embed the data.

## Accuracy

obscura ships a labelled corpus and a precision/recall harness, and the numbers below are
regenerated from it — not hand-waved. Run `go test -run AccuracyReport -v` to reproduce them,
and `TestAccuracyFloor` is a CI gate that fails the build if accuracy regresses. Roughly a third
of the corpus is adversarial negatives, so the numbers are earned rather than flattering:
timestamps and clock times, UUIDs, git SHAs and a SHA-256 digest, semantic-version strings, an
ISBN-13, RGB triples and coordinates, a Luhn-*invalid* card, checksum-failing ABNs and IBANs,
9/11/13-digit runs that are structurally identical to a routing/business number but fail their
checksum, and a netmask (`255.255.255.0`) that is also a valid grouped-phone shape. You can read
every fixture under `internal/corpus/testdata/`.

Recommended config (`pii.All()` + default secret ruleset + BPE filter), relaxed span match:

| Kind | Precision | Recall | Kind | Precision | Recall |
|---|---|---|---|---|---|
| email | 100% | 100% | gov-id | 100% | 100% |
| credit card | 100% | 100% | business-id | 100% | 100% |
| IBAN | 100% | 100% | crypto | 100% | 100% |
| routing | 100% | 100% | phone | 100% | 100% |
| IP | 100% | 100% | secret | 100% | 100% |
| MAC | 100% | 100% | | | |
| **Overall** | **100%** | **100%** | (102 spans, 11 docs) | | |

What this number does and does not mean: every detected kind is validated by a real checksum
(Luhn, IBAN mod-97, ABA, ABN mod-89, NZBN EAN-13, TFN mod-11) or a strict structural pattern,
and overlap resolution prefers a validated identifier over a loosely-matched one — so on this
corpus there are no false positives or misses. It is still a *curated, English-locale* corpus:
treat it as a regression gate and a statement of intent, not a guarantee for arbitrary text.
Names, addresses, and free-form identifiers are explicitly out of scope for the regex core
(that is the optional NER tier). Contributions of new fixtures — especially ones that break the
current detectors — are the most useful thing you can send.

## Reversibility & streaming

`Vault.Restore` reverses a whole response in one pass. For token/SSE streams use
`Vault.NewRestoreStreamer()` — it correctly restores placeholders split across delta boundaries
(and across multi-byte delimiter splits). The `Vault` implements `slog.LogValuer`, so logging
one yields only an entry count, never the secrets it holds.

## Compliance presets

```go
s := obscura.New(preset.PCI()...)   // also GDPR(), HIPAA()
```

Presets are a starting point, not legal advice.

## Extending

Detectors and filters are interfaces. Bring your own — including a caller-supplied NER model
(`ContextDetector`, run concurrently under a `context.Context`) for names/locations, which the
pure-Go core deliberately never claims to detect from regex.

```go
type Detector interface {
    Name() string
    Detect(text string) []Match
}
```

## Non-goals

- No accurate name/address detection from regex (that's the optional NER tier).
- Injection detection is a tripwire, trivially evaded by paraphrase — defense-in-depth only.
- Not a network proxy/daemon (though the transport makes building one trivial).

## License

MIT — see [LICENSE](LICENSE) and [NOTICE](NOTICE) for third-party attribution.

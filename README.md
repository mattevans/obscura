# obscura

[![Go Reference](https://pkg.go.dev/badge/github.com/mattevans/obscura.svg)](https://pkg.go.dev/github.com/mattevans/obscura)
[![Go Report Card](https://goreportcard.com/badge/github.com/mattevans/obscura)](https://goreportcard.com/report/github.com/mattevans/obscura)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Go 1.23+](https://img.shields.io/badge/Go-1.23%2B-00ADD8.svg)

Detect and **reversibly redact** PII, secrets, and prompt-injection patterns from text
*before* it leaves your process for an LLM — then restore the originals in the model's
response.

## How it works

Think of obscura as a **coat-check for your data.** Sensitive bits — an email, a card number,
an API key — are checked at the door and swapped for numbered tickets before your text reaches
the AI. The model only ever sees the tickets. When its answer comes back, obscura redeems the
tickets and puts the real values back.

```
You send:   "Email john.smith@acme.com about the invoice,
             my card is 4111 1111 1111 1111."

AI sees:    "Email ⟦EMAIL_1⟧ about the invoice,
             my card is ⟦CREDIT_CARD_1⟧."

AI replies: "Sure — I'll draft a note to ⟦EMAIL_1⟧ and
             reference ⟦CREDIT_CARD_1⟧."

You get:    "Sure — I'll draft a note to john.smith@acme.com
             and reference 4111 1111 1111 1111."
```

The same value always maps to the same ticket within a call, so the model sees a consistent
entity and restoration is unambiguous. obscura is a small, pure-Go library: the core has **no
required third-party dependencies**, embeds all its data (no runtime downloads, no telemetry),
and is safe for concurrent use.

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
| `pii` | email, phone, credit card, IBAN, routing (US ABA, UK sort code, AU BSB, NZ account), IPv4/IPv6, MAC, gov-ID (US SSN, UK NINO, AU TFN, NZ IRD), business-ID (AU ABN, NZ NZBN), BTC/ETH | Luhn, IBAN mod-97, ABA/ABN/NZBN/TFN/IRD checksums, context cues |
| `secret` | AWS, GitHub/GitLab, Slack, Stripe, Google, OpenAI/Anthropic, JWT, private keys, generic assignments | Aho-Corasick keyword pre-filter, Shannon entropy, optional BPE token-efficiency |
| `injection` | instruction-override, prompt-exfiltration, role-play, jailbreak, chat-template delimiters | heuristic tripwire (defense-in-depth, not a guarantee) |

## Locales

Phone numbers, government IDs, business IDs, and domestic bank routing codes are jurisdiction-
specific. By default every supported jurisdiction (US, GB, AU, NZ) is recognised. If you only
operate in one or two, narrow the detectors with `pii.WithLocales` to cut false positives — a
loose 3-3-4 digit group is only treated as a phone number when the relevant locale is active:

```go
s := obscura.New(
    obscura.WithDetectors(pii.All(pii.WithLocales(pii.LocaleUS, pii.LocaleGB))...),
)
```

Jurisdiction-agnostic formats are always recognised regardless of this setting: E.164 phone
numbers (`+…`) and IBANs both carry their own country code. Checksummed identifiers (IBAN, US ABA,
AU TFN/ABN, NZ NZBN/IRD) are validated outright; unchecksummed domestic codes (UK sort code,
AU BSB, NZ bank account) require a nearby cue word ("sort code", "BSB", "account") so an arbitrary
hyphenated number is not mistaken for one.

### Adding a locale

Each jurisdiction's identifier patterns live in their own `pii/locale_<cc>.go` file (e.g.
`locale_us.go`, `locale_nz.go`), so adding South Africa is an almost entirely additive change:

1. Create `pii/locale_za.go` with a `zaRules()` function returning that jurisdiction's
   `[]localeRule` — its phone, bank, gov-ID, and business-ID patterns, each tagged with the
   matching `obscura.Kind`. A checksummed identifier needs no cue; an unchecksummed one sets
   `requireCue: true` with a list of `cues`.
2. Add a `LocaleZA` constant and append `zaRules` to `localeRuleSources` in `pii/locale.go`
   (two lines).
3. Reuse a checksum from `pii/checksum.go` (e.g. `validLuhn` for a SA ID number) or add a new
   validator there if the format needs one.
4. Add labelled fixtures — including hard negatives — under `internal/corpus/testdata/`.

The kind detectors (`phone.go`, `bank.go`, `govid.go`, `business.go`) select their rules from the
registry by `Kind`, so they pick up the new locale automatically and need no edits. An internal
invariant test (`TestLocaleRuleInvariants`) checks that every rule is well-formed and every locale
is registered.

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
checksum, a netmask (`255.255.255.0`) that is also a valid grouped-phone shape, a checksum-failing NZ IRD
number, and hyphenated codes that match a sort-code or BSB shape but have no cue word nearby. You
can read every fixture under `internal/corpus/testdata/`.

Recommended config (`pii.All()` + default secret ruleset + BPE filter), relaxed span match:

| Kind | Precision | Recall | Kind | Precision | Recall |
|---|---|---|---|---|---|
| email | 100% | 100% | gov-id | 100% | 100% |
| credit card | 100% | 100% | business-id | 100% | 100% |
| IBAN | 100% | 100% | crypto | 100% | 100% |
| routing | 100% | 100% | phone | 100% | 100% |
| IP | 100% | 100% | secret | 100% | 100% |
| MAC | 100% | 100% | | | |
| **Overall** | **100%** | **100%** | (109 spans, 11 docs) | | |

What this number does and does not mean: most detected kinds are validated by a real checksum
(Luhn, IBAN mod-97, ABA, ABN mod-89, NZBN EAN-13, TFN mod-11, IRD mod-11); the unchecksummed
domestic bank codes (UK sort code, AU BSB, NZ account) instead require a nearby cue word, and
overlap resolution prefers a validated identifier over a loosely-matched one — so on this
corpus there are no false positives or misses. It is still a *curated, multi-locale* corpus:
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

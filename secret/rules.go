package secret

import "sync"

// defaultRuleSpecs is the curated built-in rule set. Patterns cover widely-used credential
// formats; high-signal format-specific rules need no entropy floor, while the generic
// assignment rule relies on one to avoid flagging ordinary prose. Pattern shapes are derived
// from publicly documented token formats (see NOTICE for attribution).
//
// Where a rule should redact only the secret and not its surrounding context, the pattern
// captures the secret in group 1.
var defaultRuleSpecs = []struct {
	id       string
	pattern  string
	keywords []string
	entropy  float64
}{
	{
		id:       "aws-access-key-id",
		pattern:  `\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16}\b`,
		keywords: []string{"AKIA", "ASIA", "AGPA", "AIDA", "AROA", "AIPA", "ANPA", "ANVA"},
	},
	{
		id:       "aws-secret-access-key",
		pattern:  `(?i)aws.{0,20}?['"]([0-9a-zA-Z/+]{40})['"]`,
		keywords: []string{"aws"},
		entropy:  4.0,
	},
	{
		id:       "github-pat",
		pattern:  `\bgh[pousr]_[0-9A-Za-z]{36}\b`,
		keywords: []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_"},
	},
	{
		id:       "github-fine-grained-pat",
		pattern:  `\bgithub_pat_[0-9A-Za-z_]{22,255}\b`,
		keywords: []string{"github_pat_"},
	},
	{
		id:       "gitlab-pat",
		pattern:  `\bglpat-[0-9A-Za-z_\-]{20}\b`,
		keywords: []string{"glpat-"},
	},
	{
		id:       "slack-token",
		pattern:  `\bxox[baprs]-[0-9A-Za-z-]{10,48}\b`,
		keywords: []string{"xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-"},
	},
	{
		id:       "slack-webhook",
		pattern:  `https://hooks\.slack\.com/services/[A-Za-z0-9+/]{40,}`,
		keywords: []string{"hooks.slack.com"},
	},
	{
		id:       "stripe-key",
		pattern:  `\b[sr]k_(?:live|test)_[0-9A-Za-z]{24,99}\b`,
		keywords: []string{"sk_live", "sk_test", "rk_live", "rk_test"},
	},
	{
		id:       "google-api-key",
		pattern:  `\bAIza[0-9A-Za-z_\-]{35}\b`,
		keywords: []string{"AIza"},
	},
	{
		id:       "google-oauth-id",
		pattern:  `\b[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com\b`,
		keywords: []string{"googleusercontent.com"},
	},
	{
		id:       "openai-key",
		pattern:  `\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b`,
		keywords: []string{"sk-"},
		entropy:  3.0,
	},
	{
		id:       "anthropic-key",
		pattern:  `\bsk-ant-[A-Za-z0-9_\-]{20,}\b`,
		keywords: []string{"sk-ant-"},
	},
	{
		id:       "npm-token",
		pattern:  `\bnpm_[0-9A-Za-z]{36}\b`,
		keywords: []string{"npm_"},
	},
	{
		id:       "sendgrid-key",
		pattern:  `\bSG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}\b`,
		keywords: []string{"SG."},
	},
	{
		id:       "jwt",
		pattern:  `\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b`,
		keywords: []string{"eyJ"},
	},
	{
		id:       "private-key-block",
		pattern:  `-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----`,
		keywords: []string{"PRIVATE KEY"},
	},
	{
		id:       "generic-assignment",
		pattern:  `(?i)(?:api[_-]?key|secret|token|password|passwd|access[_-]?key)["']?\s*[:=]\s*["']([0-9a-zA-Z\-_=/+.]{16,64})["']`,
		keywords: []string{"key", "secret", "token", "password", "passwd"},
		entropy:  3.5,
	},
}

var (
	defaultRulesOnce sync.Once
	defaultRules     RuleSet
)

// DefaultRules returns the built-in, compiled rule set. It is computed once and is safe for
// concurrent use; the returned value is read-only.
func DefaultRules() RuleSet {
	defaultRulesOnce.Do(func() {
		rules := make([]Rule, 0, len(defaultRuleSpecs))
		for _, spec := range defaultRuleSpecs {
			rules = append(rules, mustRule(spec.id, spec.pattern, spec.keywords, spec.entropy))
		}

		defaultRules = NewRuleSet(rules...)
	})

	return defaultRules
}

// mustRule compiles a rule and panics on error. It is only ever called with the package's own
// constant patterns, so a failure is a programming error caught at first use.
func mustRule(id, pattern string, keywords []string, entropy float64) Rule {
	r, err := NewRule(id, pattern, keywords, entropy)
	if err != nil {
		panic(err)
	}

	return r
}

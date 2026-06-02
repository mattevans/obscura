package secret

import "math"

// shannonBits returns the Shannon entropy of s in bits per character. Random, high-entropy
// tokens (API keys) score near the theoretical maximum for their alphabet; structured or
// repetitive strings score much lower.
func shannonBits(s string) float64 {
	if s == "" {
		return 0
	}

	var freq [256]int
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}

	n := float64(len(s))

	var bits float64

	for _, c := range freq {
		if c == 0 {
			continue
		}

		p := float64(c) / n
		bits -= p * math.Log2(p)
	}

	return bits
}

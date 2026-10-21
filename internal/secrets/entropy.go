package secrets

import "math"

// Port of Gitleaks b58d3f10 detect/utils.go:117–133 (MIT).
func shannonEntropy(data string) (entropy float64) {
	if data == "" {
		return 0
	}
	counts := make(map[rune]int)
	for _, char := range data {
		counts[char]++
	}
	invLength := 1.0 / float64(len(data))
	for _, count := range counts {
		freq := float64(count) * invLength
		entropy -= freq * math.Log2(freq)
	}
	return entropy
}

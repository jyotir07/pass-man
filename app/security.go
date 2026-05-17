package main

import (
	"crypto/sha1"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
	"time"
	"unicode"
)

// hibpRangeURL is the HIBP k-anonymity endpoint. Only the first 5 hex chars
// of SHA-1(password) are sent over the wire; the server returns every suffix
// whose prefix matches, so the full hash never leaves the machine.
const hibpRangeURL = "https://api.pwnedpasswords.com/range/"

// entropyBits estimates password strength in bits. It looks at which character
// classes appear and computes log2(poolSize) * length — a rough upper bound,
// but good enough to separate "weak" from "strong".
func entropyBits(pw string) float64 {
	if pw == "" {
		return 0
	}
	var lower, upper, digit, symbol bool
	for _, r := range pw {
		switch {
		case unicode.IsLower(r):
			lower = true
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsDigit(r):
			digit = true
		default:
			symbol = true
		}
	}
	pool := 0
	if lower {
		pool += 26
	}
	if upper {
		pool += 26
	}
	if digit {
		pool += 10
	}
	if symbol {
		pool += 32
	}
	if pool == 0 {
		return 0
	}
	return float64(len(pw)) * math.Log2(float64(pool))
}

// strengthLabel maps entropy bits to a human-readable label.
func strengthLabel(bits float64) string {
	switch {
	case bits < 40:
		return "weak"
	case bits < 60:
		return "fair"
	case bits < 80:
		return "strong"
	default:
		return "excellent"
	}
}

// reusedPasswords returns a map of password → list of "site:user" strings
// for every password used more than once.
func reusedPasswords(entries []Entry) map[string][]string {
	seen := map[string][]string{}
	for _, e := range entries {
		key := e.Pass
		seen[key] = append(seen[key], e.Site+":"+e.User)
	}
	for k, v := range seen {
		if len(v) < 2 {
			delete(seen, k)
		}
	}
	return seen
}

// hibpCheck queries the HIBP range API using k-anonymity (only the first 5
// hex chars of the SHA-1 hash are sent). Returns the breach count, or 0 if
// the password was not found.
func hibpCheck(pw string) (int, error) {
	sum := sha1.Sum([]byte(pw))
	hash := strings.ToUpper(fmt.Sprintf("%x", sum))
	prefix, suffix := hash[:5], hash[5:]

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", hibpRangeURL+prefix, nil)
	if err != nil {
		return 0, err
	}
	// Padding makes the response length-uniform so a network observer
	// can't distinguish "common" prefixes from rare ones.
	req.Header.Set("Add-Padding", "true")
	req.Header.Set("User-Agent", "passman")

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return 0, fmt.Errorf("hibp status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, err
	}

	for _, line := range strings.Split(string(body), "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), ":", 2)
		if len(parts) != 2 {
			continue
		}
		if parts[0] == suffix {
			var count int
			fmt.Sscanf(parts[1], "%d", &count)
			return count, nil
		}
	}
	return 0, nil
}

// entryAgeDays returns the number of days since the password was last
// changed (or created). Returns -1 if the entry has no timestamps (legacy).
func entryAgeDays(e Entry) int {
	ts := e.Updated
	if ts == 0 {
		ts = e.Created
	}
	if ts == 0 {
		return -1
	}
	delta := time.Since(time.Unix(ts, 0))
	return int(delta.Hours() / 24)
}

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/atotto/clipboard"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/argon2"
	"golang.org/x/term"
)

const (
	dataFile     = "data.json"
	saltFile     = ".salt"
	lockFile     = ".lock"
	maxAttempts  = 5
	lockDuration = 5 * time.Minute
)

type E struct {
	S    string `json:"site"`
	U    string `json:"user"`
	P    string `json:"pass"`
	TOTP string `json:"totp,omitempty"`
}

type LockInfo struct {
	Attempts int   `json:"attempts"`
	LockedAt int64 `json:"locked_at"`
}

func promptPass(label string) []byte {
	fmt.Print(label)
	p, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		fmt.Println("failed to read password")
		os.Exit(1)
	}
	return p
}

func getOrCreateSalt() []byte {
	salt, err := os.ReadFile(saltFile)
	if err != nil {
		salt = make([]byte, 16)
		io.ReadFull(rand.Reader, salt)
		os.WriteFile(saltFile, salt, 0600)
	}
	return salt
}

func deriveKey(pass, salt []byte) []byte {
	return argon2.IDKey(pass, salt, 1, 64*1024, 4, 32)
}

func encrypt(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	io.ReadFull(rand.Reader, nonce)
	return gcm.Seal(nonce, nonce, data, nil), nil
}

func decrypt(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(data) < ns {
		return nil, fmt.Errorf("ciphertext too short")
	}
	return gcm.Open(nil, data[:ns], data[ns:], nil)
}

// --- lockout ---

func checkLock() {
	data, err := os.ReadFile(lockFile)
	if err != nil {
		return
	}
	var li LockInfo
	json.Unmarshal(data, &li)
	if li.Attempts >= maxAttempts {
		elapsed := time.Since(time.Unix(li.LockedAt, 0))
		if elapsed < lockDuration {
			remaining := (lockDuration - elapsed).Round(time.Second)
			fmt.Printf("vault locked — too many failed attempts. try again in %s\n", remaining)
			os.Exit(1)
		}
		os.Remove(lockFile)
	}
}

func recordFailure() {
	var li LockInfo
	data, err := os.ReadFile(lockFile)
	if err == nil {
		json.Unmarshal(data, &li)
	}
	li.Attempts++
	if li.Attempts >= maxAttempts {
		li.LockedAt = time.Now().Unix()
	}
	b, _ := json.Marshal(li)
	os.WriteFile(lockFile, b, 0600)
	remaining := maxAttempts - li.Attempts
	if remaining > 0 {
		fmt.Printf("wrong master password (%d attempts remaining)\n", remaining)
	} else {
		fmt.Printf("vault locked for %s — too many failed attempts\n", lockDuration)
	}
}

func resetLock() {
	os.Remove(lockFile)
}

// --- data ---

func ld(key []byte) ([]E, bool) {
	enc, err := os.ReadFile(dataFile)
	if err != nil {
		return []E{}, true
	}
	plain, err := decrypt(enc, key)
	if err != nil {
		return nil, false
	}
	var a []E
	json.Unmarshal(plain, &a)
	return a, true
}

func sv(a []E, key []byte) {
	b, _ := json.MarshalIndent(a, "", " ")
	enc, _ := encrypt(b, key)
	os.WriteFile(dataFile, enc, 0644)
}

// --- helpers ---

func genPass(length int) string {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
	b := make([]byte, length)
	io.ReadFull(rand.Reader, b)
	for i := range b {
		b[i] = chars[int(b[i])%len(chars)]
	}
	return string(b)
}

func findEntries(a []E, site, user string) []E {
	var matches []E
	for _, e := range a {
		if e.S == site && (user == "" || e.U == user) {
			matches = append(matches, e)
		}
	}
	return matches
}

func disambiguate(matches []E, site string) int {
	if len(matches) == 1 {
		return 0
	}
	fmt.Printf("multiple entries for %q:\n", site)
	for i, e := range matches {
		fmt.Printf("  [%d] %s\n", i+1, e.U)
	}
	fmt.Print("pick one (number): ")
	var input string
	fmt.Scanln(&input)
	idx, err := strconv.Atoi(input)
	if err != nil || idx < 1 || idx > len(matches) {
		fmt.Println("invalid choice")
		os.Exit(1)
	}
	return idx - 1
}

func copyAndWaitClear(text string) {
	clipboard.WriteAll(text)
	fmt.Println("password copied to clipboard")
	fmt.Println("press enter to clear clipboard (auto-clears in 30s)")

	done := make(chan struct{})
	go func() {
		buf := make([]byte, 1)
		os.Stdin.Read(buf)
		done <- struct{}{}
	}()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
	}

	current, err := clipboard.ReadAll()
	if err == nil && current == text {
		clipboard.WriteAll("")
		fmt.Println("clipboard cleared")
	}
}

func usage() {
	fmt.Println("commands:")
	fmt.Println("  add <site> <user> <pass>     — save a password")
	fmt.Println("  get <site> [user]            — copy password to clipboard")
	fmt.Println("  list                         — show all sites")
	fmt.Println("  delete <site> [user]         — remove an entry")
	fmt.Println("  update <site> [user]         — change password for an entry")
	fmt.Println("  search <query>               — find entries by substring")
	fmt.Println("  gen [length]                 — generate a random password (default 16)")
	fmt.Println("  gen-add <site> <user> [len]  — generate and save a password")
	fmt.Println("  export [--csv]               — export vault to stdout")
	fmt.Println("  import <file>                — import from JSON or CSV file")
	fmt.Println("  totp-add <site> <secret>     — store a TOTP secret for a site")
	fmt.Println("  totp <site> [user]           — generate current TOTP code")
	fmt.Println("  change-master                — change master password")
}

func main() {
	if len(os.Args) < 2 {
		usage()
		return
	}

	cmd := os.Args[1]

	if cmd == "gen" {
		length := 16
		if len(os.Args) >= 3 {
			length, _ = strconv.Atoi(os.Args[2])
			if length <= 0 {
				length = 16
			}
		}
		fmt.Println(genPass(length))
		return
	}

	checkLock()

	salt := getOrCreateSalt()
	pass := promptPass("Master password: ")
	key := deriveKey(pass, salt)
	a, ok := ld(key)
	if !ok {
		recordFailure()
		os.Exit(1)
	}
	resetLock()

	switch cmd {
	case "add":
		if len(os.Args) < 5 {
			fmt.Println("usage: add <site> <user> <pass>")
			return
		}
		a = append(a, E{S: os.Args[2], U: os.Args[3], P: os.Args[4]})
		sv(a, key)
		fmt.Println("added")

	case "get":
		if len(os.Args) < 3 {
			fmt.Println("usage: get <site> [user]")
			return
		}
		site := os.Args[2]
		user := ""
		if len(os.Args) >= 4 {
			user = os.Args[3]
		}
		matches := findEntries(a, site, user)
		if len(matches) == 0 {
			fmt.Println("not found")
			return
		}
		idx := disambiguate(matches, site)
		fmt.Printf("user: %s\n", matches[idx].U)
		copyAndWaitClear(matches[idx].P)

	case "list":
		if len(a) == 0 {
			fmt.Println("no entries")
			return
		}
		for _, e := range a {
			fmt.Printf("  %-20s %s\n", e.S, e.U)
		}

	case "delete":
		if len(os.Args) < 3 {
			fmt.Println("usage: delete <site> [user]")
			return
		}
		site := os.Args[2]
		user := ""
		if len(os.Args) >= 4 {
			user = os.Args[3]
		}
		matches := findEntries(a, site, user)
		if len(matches) == 0 {
			fmt.Println("not found")
			return
		}
		idx := disambiguate(matches, site)
		target := matches[idx]
		var b []E
		removed := false
		for _, e := range a {
			if !removed && e.S == target.S && e.U == target.U {
				removed = true
				continue
			}
			b = append(b, e)
		}
		sv(b, key)
		fmt.Println("deleted")

	case "update":
		if len(os.Args) < 3 {
			fmt.Println("usage: update <site> [user]")
			return
		}
		site := os.Args[2]
		user := ""
		if len(os.Args) >= 4 {
			user = os.Args[3]
		}
		matches := findEntries(a, site, user)
		if len(matches) == 0 {
			fmt.Println("not found")
			return
		}
		idx := disambiguate(matches, site)
		target := matches[idx]
		newPass := promptPass("New password: ")
		if len(newPass) == 0 {
			fmt.Println("password cannot be empty")
			return
		}
		for i, e := range a {
			if e.S == target.S && e.U == target.U {
				a[i].P = string(newPass)
				break
			}
		}
		sv(a, key)
		fmt.Println("updated")

	case "search":
		if len(os.Args) < 3 {
			fmt.Println("usage: search <query>")
			return
		}
		query := strings.ToLower(os.Args[2])
		found := false
		for _, e := range a {
			if strings.Contains(strings.ToLower(e.S), query) || strings.Contains(strings.ToLower(e.U), query) {
				fmt.Printf("  %-20s %s\n", e.S, e.U)
				found = true
			}
		}
		if !found {
			fmt.Println("no matches")
		}

	case "gen-add":
		if len(os.Args) < 4 {
			fmt.Println("usage: gen-add <site> <user> [length]")
			return
		}
		site := os.Args[2]
		user := os.Args[3]
		length := 16
		if len(os.Args) >= 5 {
			length, _ = strconv.Atoi(os.Args[4])
			if length <= 0 {
				length = 16
			}
		}
		pw := genPass(length)
		a = append(a, E{S: site, U: user, P: pw})
		sv(a, key)
		fmt.Printf("generated and saved (%d chars)\n", length)
		copyAndWaitClear(pw)

	case "export":
		csvMode := len(os.Args) >= 3 && os.Args[2] == "--csv"
		if csvMode {
			w := csv.NewWriter(os.Stdout)
			w.Write([]string{"site", "user", "password", "totp_secret"})
			for _, e := range a {
				w.Write([]string{e.S, e.U, e.P, e.TOTP})
			}
			w.Flush()
		} else {
			b, _ := json.MarshalIndent(a, "", "  ")
			fmt.Println(string(b))
		}

	case "import":
		if len(os.Args) < 3 {
			fmt.Println("usage: import <file>")
			return
		}
		file := os.Args[2]
		raw, err := os.ReadFile(file)
		if err != nil {
			fmt.Printf("cannot read file: %s\n", err)
			return
		}
		var imported []E
		if strings.HasSuffix(strings.ToLower(file), ".csv") {
			r := csv.NewReader(strings.NewReader(string(raw)))
			records, err := r.ReadAll()
			if err != nil {
				fmt.Printf("invalid CSV: %s\n", err)
				return
			}
			for i, row := range records {
				if i == 0 {
					continue
				}
				if len(row) < 3 {
					continue
				}
				e := E{S: row[0], U: row[1], P: row[2]}
				if len(row) >= 4 {
					e.TOTP = row[3]
				}
				imported = append(imported, e)
			}
		} else {
			if err := json.Unmarshal(raw, &imported); err != nil {
				fmt.Printf("invalid JSON: %s\n", err)
				return
			}
		}
		a = append(a, imported...)
		sv(a, key)
		fmt.Printf("imported %d entries\n", len(imported))

	case "totp-add":
		if len(os.Args) < 4 {
			fmt.Println("usage: totp-add <site> <secret>")
			return
		}
		site := os.Args[2]
		secret := os.Args[3]
		if _, err := totp.GenerateCode(secret, time.Now()); err != nil {
			fmt.Printf("invalid TOTP secret: %s\n", err)
			return
		}
		matches := findEntries(a, site, "")
		if len(matches) == 0 {
			fmt.Printf("no entry for %q — add one first\n", site)
			return
		}
		idx := disambiguate(matches, site)
		target := matches[idx]
		for i, e := range a {
			if e.S == target.S && e.U == target.U {
				a[i].TOTP = secret
				break
			}
		}
		sv(a, key)
		fmt.Println("TOTP secret saved")

	case "totp":
		if len(os.Args) < 3 {
			fmt.Println("usage: totp <site> [user]")
			return
		}
		site := os.Args[2]
		user := ""
		if len(os.Args) >= 4 {
			user = os.Args[3]
		}
		matches := findEntries(a, site, user)
		if len(matches) == 0 {
			fmt.Println("not found")
			return
		}
		idx := disambiguate(matches, site)
		e := matches[idx]
		if e.TOTP == "" {
			fmt.Println("no TOTP secret for this entry — use totp-add first")
			return
		}
		code, err := totp.GenerateCode(e.TOTP, time.Now())
		if err != nil {
			fmt.Printf("failed to generate TOTP: %s\n", err)
			return
		}
		clipboard.WriteAll(code)
		fmt.Printf("TOTP: %s (copied to clipboard)\n", code)

	case "change-master":
		newPass := promptPass("New master password: ")
		confirm := promptPass("Confirm new password: ")
		if string(newPass) != string(confirm) {
			fmt.Println("passwords do not match")
			return
		}
		if len(newPass) == 0 {
			fmt.Println("password cannot be empty")
			return
		}
		newKey := deriveKey(newPass, salt)
		sv(a, newKey)
		fmt.Println("master password changed")

	default:
		usage()
	}
}

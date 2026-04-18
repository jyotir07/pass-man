package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/atotto/clipboard"
	"github.com/pquerna/otp/totp"
	"golang.org/x/term"
)

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

func findEntries(entries []Entry, site, user string) []Entry {
	var matches []Entry
	for _, e := range entries {
		if e.Site == site && (user == "" || e.User == user) {
			matches = append(matches, e)
		}
	}
	return matches
}

func disambiguate(matches []Entry, site string) int {
	if len(matches) == 1 {
		return 0
	}
	fmt.Printf("multiple entries for %q:\n", site)
	for i, e := range matches {
		fmt.Printf("  [%d] %s\n", i+1, e.User)
	}
	fmt.Print("pick one (number): ")
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	idx, err := strconv.Atoi(strings.TrimSpace(input))
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

func saveOrDie(v *Vault, key []byte) {
	if err := saveVault(v, key); err != nil {
		fmt.Printf("save failed: %s\n", err)
		os.Exit(1)
	}
}

func runCommand(cmd string, args []string, v *Vault, key, salt []byte) {
	switch cmd {
	case "add":
		if len(args) < 3 {
			fmt.Println("usage: add <site> <user> <pass>")
			return
		}
		v.Entries = append(v.Entries, Entry{Site: args[0], User: args[1], Pass: args[2]})
		saveOrDie(v, key)
		fmt.Println("added")

	case "get":
		if len(args) < 1 {
			fmt.Println("usage: get <site> [user]")
			return
		}
		user := ""
		if len(args) >= 2 {
			user = args[1]
		}
		matches := findEntries(v.Entries, args[0], user)
		if len(matches) == 0 {
			fmt.Println("not found")
			return
		}
		idx := disambiguate(matches, args[0])
		fmt.Printf("user: %s\n", matches[idx].User)
		copyAndWaitClear(matches[idx].Pass)

	case "list":
		if len(v.Entries) == 0 {
			fmt.Println("no entries")
			return
		}
		for _, e := range v.Entries {
			fmt.Printf("  %-20s %s\n", e.Site, e.User)
		}

	case "delete":
		if len(args) < 1 {
			fmt.Println("usage: delete <site> [user]")
			return
		}
		user := ""
		if len(args) >= 2 {
			user = args[1]
		}
		matches := findEntries(v.Entries, args[0], user)
		if len(matches) == 0 {
			fmt.Println("not found")
			return
		}
		idx := disambiguate(matches, args[0])
		target := matches[idx]
		kept := make([]Entry, 0, len(v.Entries))
		removed := false
		for _, e := range v.Entries {
			if !removed && e.Site == target.Site && e.User == target.User {
				removed = true
				continue
			}
			kept = append(kept, e)
		}
		v.Entries = kept
		saveOrDie(v, key)
		fmt.Println("deleted")

	case "update":
		if len(args) < 1 {
			fmt.Println("usage: update <site> [user]")
			return
		}
		user := ""
		if len(args) >= 2 {
			user = args[1]
		}
		matches := findEntries(v.Entries, args[0], user)
		if len(matches) == 0 {
			fmt.Println("not found")
			return
		}
		idx := disambiguate(matches, args[0])
		target := matches[idx]
		newPass := promptPass("New password: ")
		if len(newPass) == 0 {
			fmt.Println("password cannot be empty")
			return
		}
		for i, e := range v.Entries {
			if e.Site == target.Site && e.User == target.User {
				v.Entries[i].Pass = string(newPass)
				break
			}
		}
		saveOrDie(v, key)
		fmt.Println("updated")

	case "search":
		if len(args) < 1 {
			fmt.Println("usage: search <query>")
			return
		}
		query := strings.ToLower(args[0])
		found := false
		for _, e := range v.Entries {
			if strings.Contains(strings.ToLower(e.Site), query) || strings.Contains(strings.ToLower(e.User), query) {
				fmt.Printf("  %-20s %s\n", e.Site, e.User)
				found = true
			}
		}
		if !found {
			fmt.Println("no matches")
		}

	case "gen-add":
		if len(args) < 2 {
			fmt.Println("usage: gen-add <site> <user> [length]")
			return
		}
		length := 16
		if len(args) >= 3 {
			length, _ = strconv.Atoi(args[2])
			if length <= 0 {
				length = 16
			}
		}
		pw := genPass(length)
		v.Entries = append(v.Entries, Entry{Site: args[0], User: args[1], Pass: pw})
		saveOrDie(v, key)
		fmt.Printf("generated and saved (%d chars)\n", length)
		copyAndWaitClear(pw)

	case "export":
		csvMode := len(args) >= 1 && args[0] == "--csv"
		if csvMode {
			w := csv.NewWriter(os.Stdout)
			w.Write([]string{"site", "user", "password", "totp_secret"})
			for _, e := range v.Entries {
				w.Write([]string{e.Site, e.User, e.Pass, e.TOTP})
			}
			w.Flush()
		} else {
			b, _ := json.MarshalIndent(v.Entries, "", "  ")
			fmt.Println(string(b))
		}

	case "import":
		if len(args) < 1 {
			fmt.Println("usage: import <file>")
			return
		}
		file := args[0]
		raw, err := os.ReadFile(file)
		if err != nil {
			fmt.Printf("cannot read file: %s\n", err)
			return
		}
		var imported []Entry
		if strings.HasSuffix(strings.ToLower(file), ".csv") {
			r := csv.NewReader(strings.NewReader(string(raw)))
			records, err := r.ReadAll()
			if err != nil {
				fmt.Printf("invalid CSV: %s\n", err)
				return
			}
			for i, row := range records {
				if i == 0 || len(row) < 3 {
					continue
				}
				e := Entry{Site: row[0], User: row[1], Pass: row[2]}
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
		v.Entries = append(v.Entries, imported...)
		saveOrDie(v, key)
		fmt.Printf("imported %d entries\n", len(imported))

	case "totp-add":
		if len(args) < 2 {
			fmt.Println("usage: totp-add <site> <secret>")
			return
		}
		site, secret := args[0], args[1]
		if _, err := totp.GenerateCode(secret, time.Now()); err != nil {
			fmt.Printf("invalid TOTP secret: %s\n", err)
			return
		}
		matches := findEntries(v.Entries, site, "")
		if len(matches) == 0 {
			fmt.Printf("no entry for %q — add one first\n", site)
			return
		}
		idx := disambiguate(matches, site)
		target := matches[idx]
		for i, e := range v.Entries {
			if e.Site == target.Site && e.User == target.User {
				v.Entries[i].TOTP = secret
				break
			}
		}
		saveOrDie(v, key)
		fmt.Println("TOTP secret saved")

	case "totp":
		if len(args) < 1 {
			fmt.Println("usage: totp <site> [user]")
			return
		}
		user := ""
		if len(args) >= 2 {
			user = args[1]
		}
		matches := findEntries(v.Entries, args[0], user)
		if len(matches) == 0 {
			fmt.Println("not found")
			return
		}
		idx := disambiguate(matches, args[0])
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
		saveOrDie(v, newKey)
		fmt.Println("master password changed")

	default:
		usage()
	}
}

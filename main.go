package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/atotto/clipboard"
	"golang.org/x/crypto/argon2"
	"golang.org/x/term"
)

const dataFile = "data.json"
const saltFile = ".salt"

type E struct {
	S string `json:"site"`
	U string `json:"user"`
	P string `json:"pass"`
}

func masterPass() []byte {
	fmt.Print("Master password: ")
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

func ld(key []byte) []E {
	enc, err := os.ReadFile(dataFile)
	if err != nil {
		return []E{}
	}
	plain, err := decrypt(enc, key)
	if err != nil {
		fmt.Println("wrong master password or corrupted data")
		os.Exit(1)
	}
	var a []E
	json.Unmarshal(plain, &a)
	return a
}

func sv(a []E, key []byte) {
	b, _ := json.MarshalIndent(a, "", " ")
	enc, _ := encrypt(b, key)
	os.WriteFile(dataFile, enc, 0644)
}

func genPass(length int) string {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
	b := make([]byte, length)
	io.ReadFull(rand.Reader, b)
	for i := range b {
		b[i] = chars[int(b[i])%len(chars)]
	}
	return string(b)
}

func usage() {
	fmt.Println("commands:")
	fmt.Println("  add <site> <user> <pass>  — save a password")
	fmt.Println("  get <site>                — copy password to clipboard")
	fmt.Println("  list                      — show all sites")
	fmt.Println("  delete <site>             — remove an entry")
	fmt.Println("  gen [length]              — generate a random password (default 16)")
}

func main() {
	if len(os.Args) < 2 {
		usage()
		return
	}

	cmd := os.Args[1]

	// gen needs no master password
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

	salt := getOrCreateSalt()
	pass := masterPass()
	key := deriveKey(pass, salt)
	a := ld(key)

	switch cmd {
	case "add":
		if len(os.Args) < 5 {
			fmt.Println("usage: add <site> <user> <pass>")
			return
		}
		a = append(a, E{os.Args[2], os.Args[3], os.Args[4]})
		sv(a, key)
		fmt.Println("added")

	case "get":
		if len(os.Args) < 3 {
			fmt.Println("usage: get <site>")
			return
		}
		for _, e := range a {
			if e.S == os.Args[2] {
				clipboard.WriteAll(e.P)
				fmt.Printf("user: %s\npassword copied to clipboard\n", e.U)
				return
			}
		}
		fmt.Println("not found")

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
			fmt.Println("usage: delete <site>")
			return
		}
		site := os.Args[2]
		var b []E
		found := false
		for _, e := range a {
			if e.S == site {
				found = true
				continue
			}
			b = append(b, e)
		}
		if !found {
			fmt.Println("not found")
			return
		}
		sv(b, key)
		fmt.Println("deleted")

	default:
		usage()
	}
}

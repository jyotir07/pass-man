package main

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
)

func randKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, keySize)
	if _, err := io.ReadFull(rand.Reader, k); err != nil {
		t.Fatalf("rand key: %v", err)
	}
	return k
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := randKey(t)
	cases := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"short", []byte("hello")},
		{"json", []byte(`{"site":"example.com","user":"a","pass":"b"}`)},
		{"binary", bytes.Repeat([]byte{0x00, 0xff, 0x42}, 1024)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ct, err := encrypt(tc.data, key)
			if err != nil {
				t.Fatalf("encrypt: %v", err)
			}
			pt, err := decrypt(ct, key)
			if err != nil {
				t.Fatalf("decrypt: %v", err)
			}
			if !bytes.Equal(pt, tc.data) {
				t.Fatalf("round-trip mismatch: got %q want %q", pt, tc.data)
			}
		})
	}
}

func TestDecryptWithWrongKeyFails(t *testing.T) {
	k1, k2 := randKey(t), randKey(t)
	ct, err := encrypt([]byte("secret"), k1)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := decrypt(ct, k2); err == nil {
		t.Fatal("decrypt with wrong key should fail")
	}
}

func TestDecryptCorruptedFails(t *testing.T) {
	key := randKey(t)
	ct, err := encrypt([]byte("secret"), key)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	ct[len(ct)-1] ^= 0xff // corrupt auth tag
	if _, err := decrypt(ct, key); err == nil {
		t.Fatal("decrypt of corrupted ciphertext should fail")
	}
}

func TestDecryptTooShortFails(t *testing.T) {
	key := randKey(t)
	if _, err := decrypt([]byte{1, 2, 3}, key); err == nil {
		t.Fatal("decrypt of too-short input should fail")
	}
}

func TestEncryptNonceUniqueness(t *testing.T) {
	key := randKey(t)
	plain := []byte("same plaintext")
	a, _ := encrypt(plain, key)
	b, _ := encrypt(plain, key)
	if bytes.Equal(a, b) {
		t.Fatal("two encryptions of the same plaintext must differ (nonce reuse)")
	}
}

func TestDeriveKeyDeterministic(t *testing.T) {
	pass := []byte("correct horse battery staple")
	salt := []byte("0123456789abcdef")
	k1 := deriveKey(pass, salt)
	k2 := deriveKey(pass, salt)
	if !bytes.Equal(k1, k2) {
		t.Fatal("deriveKey must be deterministic for same inputs")
	}
	if len(k1) != keySize {
		t.Fatalf("key length = %d, want %d", len(k1), keySize)
	}
}

func TestDeriveKeyDiffersOnSalt(t *testing.T) {
	pass := []byte("correct horse battery staple")
	k1 := deriveKey(pass, []byte("0123456789abcdef"))
	k2 := deriveKey(pass, []byte("fedcba9876543210"))
	if bytes.Equal(k1, k2) {
		t.Fatal("deriveKey should differ with different salts")
	}
}

func TestDeriveKeyDiffersOnPass(t *testing.T) {
	salt := []byte("0123456789abcdef")
	k1 := deriveKey([]byte("pass1"), salt)
	k2 := deriveKey([]byte("pass2"), salt)
	if bytes.Equal(k1, k2) {
		t.Fatal("deriveKey should differ with different passwords")
	}
}

func TestGenPassLength(t *testing.T) {
	for _, n := range []int{1, 8, 16, 64} {
		p := genPass(n)
		if len(p) != n {
			t.Errorf("genPass(%d) length = %d", n, len(p))
		}
	}
}

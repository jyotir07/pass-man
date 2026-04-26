package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestParseVaultV4(t *testing.T) {
	v4 := []byte(`{"version":4,"entries":[{"site":"x","user":"u","pass":"p"}]}`)
	got, err := parseVault(v4)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.Version != 4 {
		t.Errorf("version = %d, want 4", got.Version)
	}
	if len(got.Entries) != 1 || got.Entries[0].Site != "x" {
		t.Errorf("entries mismatch: %+v", got.Entries)
	}
}

func TestParseVaultLegacy(t *testing.T) {
	legacy := []byte(`[{"site":"x","user":"u","pass":"p"}]`)
	got, err := parseVault(legacy)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.Version != vaultVersion {
		t.Errorf("version = %d, want %d", got.Version, vaultVersion)
	}
	if len(got.Entries) != 1 || got.Entries[0].Site != "x" {
		t.Errorf("entries mismatch: %+v", got.Entries)
	}
}

func TestParseVaultEmpty(t *testing.T) {
	got, err := parseVault([]byte(""))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got.Entries) != 0 {
		t.Errorf("entries = %v, want empty", got.Entries)
	}
	if got.Version != vaultVersion {
		t.Errorf("version = %d, want %d", got.Version, vaultVersion)
	}
}

func TestParseVaultInvalid(t *testing.T) {
	if _, err := parseVault([]byte("{not valid json")); err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestAtomicWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "data.json")

	if err := atomicWrite(path, []byte("v1"), 0600); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if err := atomicWrite(path, []byte("v2"), 0600); err != nil {
		t.Fatalf("overwrite: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "v2" {
		t.Fatalf("content = %q, want %q", got, "v2")
	}

	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.Name() != "data.json" {
			t.Errorf("unexpected leftover file: %s", e.Name())
		}
	}
}

func TestSaveLoadVaultRoundTrip(t *testing.T) {
	dir := t.TempDir()
	orig := dataFile
	dataFile = filepath.Join(dir, "vault.bin")
	defer func() { dataFile = orig }()

	key := make([]byte, keySize)
	for i := range key {
		key[i] = byte(i)
	}

	v := &Vault{
		Entries: []Entry{
			{Site: "a", User: "u1", Pass: "p1"},
			{Site: "b", User: "u2", Pass: "p2", TOTP: "JBSWY3DPEHPK3PXP"},
		},
	}
	if err := saveVault(v, key); err != nil {
		t.Fatalf("save: %v", err)
	}

	got, err := loadVault(key)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.Version != vaultVersion {
		t.Errorf("version = %d, want %d", got.Version, vaultVersion)
	}
	if len(got.Entries) != 2 {
		t.Fatalf("entries count = %d, want 2", len(got.Entries))
	}
	if got.Entries[1].TOTP != "JBSWY3DPEHPK3PXP" {
		t.Errorf("totp not preserved: %+v", got.Entries[1])
	}

	raw, _ := os.ReadFile(dataFile)
	if bytes.Contains(raw, []byte("p1")) {
		t.Error("plaintext password found in encrypted vault file")
	}
}

func TestLoadVaultWrongKey(t *testing.T) {
	dir := t.TempDir()
	orig := dataFile
	dataFile = filepath.Join(dir, "vault.bin")
	defer func() { dataFile = orig }()

	k1 := bytes.Repeat([]byte{1}, keySize)
	k2 := bytes.Repeat([]byte{2}, keySize)

	v := &Vault{Entries: []Entry{{Site: "x", User: "u", Pass: "p"}}}
	if err := saveVault(v, k1); err != nil {
		t.Fatalf("save: %v", err)
	}
	if _, err := loadVault(k2); err == nil {
		t.Fatal("loadVault with wrong key should error")
	}
}

func TestLoadVaultMissingFile(t *testing.T) {
	dir := t.TempDir()
	orig := dataFile
	dataFile = filepath.Join(dir, "does-not-exist.bin")
	defer func() { dataFile = orig }()

	key := bytes.Repeat([]byte{1}, keySize)
	v, err := loadVault(key)
	if err != nil {
		t.Fatalf("missing file should not error: %v", err)
	}
	if len(v.Entries) != 0 {
		t.Errorf("expected empty vault, got %+v", v.Entries)
	}
}

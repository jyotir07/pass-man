package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestZeroize(t *testing.T) {
	b := []byte{1, 2, 3, 4, 5}
	zeroize(b)
	for i, v := range b {
		if v != 0 {
			t.Fatalf("byte %d not zeroed: %d", i, v)
		}
	}
}

func TestEntropyBitsClassesIncreasePool(t *testing.T) {
	lower := entropyBits("aaaaaaaa")     // 8 * log2(26)
	mixed := entropyBits("Aa1!Aa1!")     // 8 * log2(94)
	if mixed <= lower {
		t.Fatalf("mixed (%f) should beat lower-only (%f)", mixed, lower)
	}
}

func TestEntropyBitsLengthMatters(t *testing.T) {
	short := entropyBits("Aa1!")
	long := entropyBits("Aa1!Aa1!Aa1!Aa1!")
	if long <= short {
		t.Fatalf("longer (%f) should beat shorter (%f)", long, short)
	}
}

func TestStrengthLabels(t *testing.T) {
	cases := []struct {
		bits float64
		want string
	}{
		{20, "weak"},
		{50, "fair"},
		{70, "strong"},
		{120, "excellent"},
	}
	for _, c := range cases {
		if got := strengthLabel(c.bits); got != c.want {
			t.Errorf("strengthLabel(%v) = %s, want %s", c.bits, got, c.want)
		}
	}
}

func TestReusedPasswords(t *testing.T) {
	entries := []Entry{
		{Site: "a", User: "u1", Pass: "shared"},
		{Site: "b", User: "u2", Pass: "shared"},
		{Site: "c", User: "u3", Pass: "unique"},
	}
	reused := reusedPasswords(entries)
	if len(reused) != 1 {
		t.Fatalf("reused count = %d, want 1", len(reused))
	}
	if _, ok := reused["shared"]; !ok {
		t.Fatal("expected 'shared' in reused map")
	}
	if _, ok := reused["unique"]; ok {
		t.Fatal("'unique' should not be in reused map")
	}
}

func TestEntryAgeDaysLegacy(t *testing.T) {
	if got := entryAgeDays(Entry{}); got != -1 {
		t.Fatalf("legacy entry age = %d, want -1", got)
	}
}

func TestEntryAgeDaysUsesUpdated(t *testing.T) {
	tenDaysAgo := time.Now().Unix() - 10*86400
	got := entryAgeDays(Entry{Created: tenDaysAgo - 86400, Updated: tenDaysAgo})
	if got < 9 || got > 11 {
		t.Fatalf("age = %d, want ~10", got)
	}
}

func TestRotateBackup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.bin")
	if err := os.WriteFile(path, []byte("v1"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := rotateBackup(path); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	bak, err := os.ReadFile(path + ".bak")
	if err != nil {
		t.Fatalf("read backup: %v", err)
	}
	if !bytes.Equal(bak, []byte("v1")) {
		t.Fatalf("backup content = %q, want v1", bak)
	}
}

func TestRotateBackupMissingSourceIsNoop(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "missing.bin")
	if err := rotateBackup(path); err != nil {
		t.Fatalf("missing source should not error: %v", err)
	}
	if _, err := os.Stat(path + ".bak"); !os.IsNotExist(err) {
		t.Fatal("backup should not be created when source is missing")
	}
}

func TestSaveVaultCreatesBackup(t *testing.T) {
	dir := t.TempDir()
	orig := dataFile
	dataFile = filepath.Join(dir, "vault.bin")
	defer func() { dataFile = orig }()

	key := make([]byte, keySize)
	for i := range key {
		key[i] = byte(i)
	}

	if err := saveVault(&Vault{Entries: []Entry{{Site: "a", User: "u", Pass: "p1"}}}, key); err != nil {
		t.Fatalf("first save: %v", err)
	}
	first, _ := os.ReadFile(dataFile)

	if err := saveVault(&Vault{Entries: []Entry{{Site: "a", User: "u", Pass: "p2"}}}, key); err != nil {
		t.Fatalf("second save: %v", err)
	}

	bak, err := os.ReadFile(dataFile + ".bak")
	if err != nil {
		t.Fatalf("backup file missing: %v", err)
	}
	if !bytes.Equal(bak, first) {
		t.Fatal("backup does not match the previous vault content")
	}
}

func TestParseVaultV5WithTimestamps(t *testing.T) {
	raw := []byte(`{"version":5,"entries":[{"site":"x","user":"u","pass":"p","created":1700000000,"updated":1700000001}]}`)
	v, err := parseVault(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if v.Version != 5 {
		t.Errorf("version = %d, want 5", v.Version)
	}
	if v.Entries[0].Created != 1700000000 || v.Entries[0].Updated != 1700000001 {
		t.Errorf("timestamps not preserved: %+v", v.Entries[0])
	}
}

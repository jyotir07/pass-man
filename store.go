package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	saltFile     = ".salt"
	lockFile     = ".lock"
	maxAttempts  = 5
	lockDuration = 5 * time.Minute
	vaultVersion = 4
)

// Overridable for tests.
var dataFile = "data.json"

type Entry struct {
	Site string `json:"site"`
	User string `json:"user"`
	Pass string `json:"pass"`
	TOTP string `json:"totp,omitempty"`
}

type Vault struct {
	Version int     `json:"version"`
	Entries []Entry `json:"entries"`
}

type LockInfo struct {
	Attempts int   `json:"attempts"`
	LockedAt int64 `json:"locked_at"`
}

func loadVault(key []byte) (*Vault, error) {
	enc, err := os.ReadFile(dataFile)
	if err != nil {
		// Any read error (incl. missing file) → fresh vault.
		return &Vault{Version: vaultVersion}, nil
	}
	plain, err := decrypt(enc, key)
	if err != nil {
		return nil, err
	}
	return parseVault(plain)
}

func parseVault(plain []byte) (*Vault, error) {
	trimmed := bytes.TrimSpace(plain)
	if len(trimmed) == 0 {
		return &Vault{Version: vaultVersion}, nil
	}
	// Legacy v3 format: a top-level JSON array of entries.
	if trimmed[0] == '[' {
		var entries []Entry
		if err := json.Unmarshal(plain, &entries); err != nil {
			return nil, fmt.Errorf("parse legacy vault: %w", err)
		}
		return &Vault{Version: vaultVersion, Entries: entries}, nil
	}
	var v Vault
	if err := json.Unmarshal(plain, &v); err != nil {
		return nil, fmt.Errorf("parse vault: %w", err)
	}
	if v.Version == 0 {
		v.Version = vaultVersion
	}
	return &v, nil
}

func saveVault(v *Vault, key []byte) error {
	v.Version = vaultVersion
	b, err := json.MarshalIndent(v, "", " ")
	if err != nil {
		return err
	}
	enc, err := encrypt(b, key)
	if err != nil {
		return err
	}
	return atomicWrite(dataFile, enc, 0600)
}

func atomicWrite(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if dir == "" {
		dir = "."
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() {
		tmp.Close()
		os.Remove(tmpName)
	}
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return err
	}
	return nil
}

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

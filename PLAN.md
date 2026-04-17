# passman — Development Plan

## v1 (done)
- [x] `add <site> <user> <pass>` — save a password
- [x] `get <site>` — retrieve a password
- [x] Store data in `data.json` (plaintext)

## v2 (done)
- [x] AES-256-GCM encryption on the data file
- [x] Argon2id key derivation from master password
- [x] Master password prompt (hidden input via `golang.org/x/term`)
- [x] `list` — show all saved sites and usernames
- [x] `delete <site>` — remove an entry
- [x] `gen [length]` — generate a cryptographically random password
- [x] `get` copies password to clipboard instead of printing it

## v3 (done)
- [x] `update <site>` — change the password for an existing entry
- [x] Multiple accounts per site (e.g. two Gmail accounts)
- [x] `search <query>` — substring/fuzzy match across site names
- [x] `export` — decrypt and dump to stdout (for backup/migration)
- [x] `import` — load from a plaintext CSV or JSON file
- [x] Lock after N failed master password attempts

## v4 (planned) — code quality
- [ ] Split `main.go` into `crypto.go`, `store.go`, `cmd.go`
- [ ] Rename one-letter types/funcs (`E`, `ld`, `sv`) to readable names
- [ ] Add tests for encrypt/decrypt round-trip and key derivation
- [ ] Vault format versioning (`"version": 4` header) for future migrations
- [ ] Atomic writes (`tmp + rename`) so a crash mid-save can't corrupt the vault

## v5 (planned) — security hardening
- [ ] Clipboard auto-clear after N seconds
- [ ] Auto-lock / re-prompt master password on idle
- [ ] In-memory key zeroization after use
- [ ] Password strength meter
- [ ] Offline HIBP k-anonymity breach check
- [ ] Backup rotation (`data.json.bak`) on every save
- [ ] Don't accept `pass` as a CLI arg for `add` — prompt hidden (shell history leaks it)

## v6 (planned) — usability
- [ ] Interactive REPL mode — unlock once, run many commands
- [ ] `change-master` — re-derive key and re-encrypt the vault
- [ ] TOTP / 2FA secret storage with `otp <site>`
- [ ] Tags / categories and `list --tag work`
- [ ] Per-entry `notes` and `url` fields
- [ ] Optional Git-backed sync (encrypted blob is safe to push)

## Notes

**Storage format changed in v2.**
`data.json` is now encrypted binary. Old plaintext `data.json` files from v1 are not compatible — re-add entries after upgrading.

The salt used for key derivation is stored in `.salt` (auto-created on first run). Back this file up alongside `data.json` — losing it means losing access to your vault.

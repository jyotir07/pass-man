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
- [x] `update <site> [user]` — change the password for an existing entry
- [x] Multiple accounts per site (disambiguation prompt when ambiguous)
- [x] `search <query>` — substring match across site names and usernames
- [x] `export [--csv]` — decrypt and dump to stdout as JSON or CSV
- [x] `import <file>` — load from a plaintext CSV or JSON file
- [x] Lock after 5 failed master password attempts (5-minute lockout)
- [x] `gen-add <site> <user> [length]` — generate and save in one step
- [x] Auto-clear clipboard after 30 seconds (or on Enter)
- [x] `change-master` — re-encrypt vault with a new master password
- [x] `totp-add <site> <secret>` — store a TOTP secret for an entry
- [x] `totp <site> [user]` — generate and copy current TOTP code

## v4 (ideas)
- [ ] Interactive TUI mode (browse/search entries without re-entering master password)
- [ ] Vault backup to encrypted file (portable, restorable on another machine)
- [ ] Browser extension or HTTP API for autofill
- [ ] Sync across devices (encrypted cloud storage)
- [ ] Password strength audit (flag weak/reused passwords)
- [ ] Expiry reminders (flag passwords older than N days)

## Notes

**Storage format changed in v2.**
`data.json` is now encrypted binary. Old plaintext `data.json` files from v1 are not compatible — re-add entries after upgrading.

The salt used for key derivation is stored in `.salt` (auto-created on first run). Back this file up alongside `data.json` — losing it means losing access to your vault.

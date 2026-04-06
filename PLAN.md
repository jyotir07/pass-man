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

## v3 (planned)
- [ ] `update <site>` — change the password for an existing entry
- [ ] Multiple accounts per site (e.g. two Gmail accounts)
- [ ] `search <query>` — substring/fuzzy match across site names
- [ ] `export` — decrypt and dump to stdout (for backup/migration)
- [ ] `import` — load from a plaintext CSV or JSON file
- [ ] Lock after N failed master password attempts

## Notes

**Storage format changed in v2.**
`data.json` is now encrypted binary. Old plaintext `data.json` files from v1 are not compatible — re-add entries after upgrading.

The salt used for key derivation is stored in `.salt` (auto-created on first run). Back this file up alongside `data.json` — losing it means losing access to your vault.

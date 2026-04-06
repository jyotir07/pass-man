# passman

A minimal CLI password manager written in Go.

## Commands

```
add <site> <user> <pass>   save a password
get <site>                 copy password to clipboard
list                       show all saved sites
delete <site>              remove an entry
gen [length]               generate a random password (default 16)
```

## Usage

```
$ go run main.go add github jyotir myPass123
Master password: 
added

$ go run main.go list
Master password: 
  github               jyotir

$ go run main.go get github
Master password: 
user: jyotir
password copied to clipboard

$ go run main.go delete github
Master password: 
deleted

$ go run main.go gen 20
xK#3mBq!Zv@9pLw&Tn2Y
```

## How it works

- All passwords are stored encrypted in `data.json` using **AES-256-GCM**
- The encryption key is derived from your master password using **Argon2id**
- A random salt is stored in `.salt` (auto-created on first run)
- `get` copies the password directly to your clipboard — nothing is printed

## Important

- Back up both `data.json` and `.salt` — losing `.salt` means losing access to your vault
- `data.json` from v1 (plaintext) is not compatible with v2 — re-add your entries after upgrading

## Roadmap

See [PLAN.md](PLAN.md) for what's done and what's coming.

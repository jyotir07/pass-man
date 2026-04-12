# passman

A minimal CLI password manager written in Go. All passwords are encrypted with AES-256-GCM and locked behind a master password.

---

## Setup

**Run without building:**
```bash
go run main.go <command>
```

**Or build once and use the binary:**
```bash
go build -o passman.exe .
./passman.exe <command>
```

The first time you run any command (except `gen`), a `.salt` file is created automatically. From then on, every command will prompt for your master password.

---

## Commands

### `add` — Save a password
```
passman.exe add <site> <user> <password>
```
```
$ ./passman.exe add github jyotir myPass123
Master password:
added
```

---

### `get` — Retrieve a password
```
passman.exe get <site>
```
Prints the username and **copies the password silently to your clipboard** — nothing sensitive is shown on screen.
```
$ ./passman.exe get github
Master password:
user: jyotir
password copied to clipboard
```

---

### `list` — Show all saved entries
```
passman.exe list
```
Shows all sites and their usernames. Passwords are never shown.
```
$ ./passman.exe list
Master password:
  github               jyotir
  google               jyotir.aditya@gmail.com
  aws                  jyotir07
```

---

### `delete` — Remove an entry
```
passman.exe delete <site>
```
```
$ ./passman.exe delete aws
Master password:
deleted
```

---

### `gen` — Generate a random password
```
passman.exe gen [length]
```
Does **not** require a master password. Generates a cryptographically random password using letters, numbers, and symbols. Default length is 16.
```
$ ./passman.exe gen
xK#3mBq!Zv@9pLw&

$ ./passman.exe gen 24
xK#3mBq!Zv@9pLw&Tn2Y!s8F
```
Tip — generate and save in one go:
```
$ ./passman.exe gen 20
Kx!9mZv#Bq3pLw&Tn2Y

$ ./passman.exe add github jyotir Kx!9mZv#Bq3pLw&Tn2Y
Master password:
added
```

---

## How it works

| What | How |
|------|-----|
| Encryption | AES-256-GCM |
| Key derivation | Argon2id (from master password + salt) |
| Storage | `data.json` (encrypted binary) |
| Salt | `.salt` (auto-created on first run) |
| Clipboard | Password is copied, never printed |

---

## Important

- **Back up both `data.json` and `.salt`** — losing `.salt` means you cannot decrypt your vault, even with the correct master password.
- If you forget your master password, there is no recovery.
- `data.json` from v1 (plaintext) is not compatible — re-add entries after upgrading.

---

## Roadmap

See [PLAN.md](PLAN.md).

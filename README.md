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
passman.exe get <site> [user]
```
Copies the password to your clipboard and auto-clears it after 30 seconds (or press Enter to clear immediately).
```
$ ./passman.exe get github
Master password:
user: jyotir
password copied to clipboard
press enter to clear clipboard (auto-clears in 30s)
clipboard cleared
```
If a site has multiple accounts, you'll be prompted to pick one — or pass the username directly:
```
$ ./passman.exe get gmail work@gmail.com
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
passman.exe delete <site> [user]
```
```
$ ./passman.exe delete aws
Master password:
deleted
```

---

### `update` — Change a password
```
passman.exe update <site> [user]
```
Prompts for the new password (hidden input).
```
$ ./passman.exe update github
Master password:
New password:
updated
```

---

### `search` — Find entries
```
passman.exe search <query>
```
Substring match across site names and usernames (case-insensitive).
```
$ ./passman.exe search git
Master password:
  github               jyotir
  gitlab               jyotir07
```

---

### `gen` — Generate a random password
```
passman.exe gen [length]
```
Does **not** require a master password. Default length is 16.
```
$ ./passman.exe gen
xK#3mBq!Zv@9pLw&

$ ./passman.exe gen 24
xK#3mBq!Zv@9pLw&Tn2Y!s8F
```

---

### `gen-add` — Generate and save in one step
```
passman.exe gen-add <site> <user> [length]
```
Generates a password, saves the entry, and copies it to clipboard.
```
$ ./passman.exe gen-add github jyotir 20
Master password:
generated and saved (20 chars)
password copied to clipboard
press enter to clear clipboard (auto-clears in 30s)
```

---

### `export` — Export your vault
```
passman.exe export [--csv]
```
Decrypts and prints all entries to stdout. Default format is JSON; use `--csv` for CSV.
```
$ ./passman.exe export > backup.json
$ ./passman.exe export --csv > backup.csv
```

---

### `import` — Import entries
```
passman.exe import <file>
```
Imports entries from a JSON or CSV file (detected by file extension). CSV files should have a header row: `site,user,password,totp_secret`.
```
$ ./passman.exe import backup.json
Master password:
imported 5 entries
```

---

### `totp-add` — Store a TOTP secret
```
passman.exe totp-add <site> <secret>
```
Attaches a TOTP secret to an existing entry. If the site has multiple accounts, you'll be prompted to pick one.
```
$ ./passman.exe totp-add github JBSWY3DPEHPK3PXP
Master password:
TOTP secret saved
```

---

### `totp` — Generate a TOTP code
```
passman.exe totp <site> [user]
```
Generates the current 6-digit TOTP code and copies it to clipboard.
```
$ ./passman.exe totp github
Master password:
TOTP: 482931 (copied to clipboard)
```

---

### `change-master` — Change your master password
```
passman.exe change-master
```
Re-encrypts the entire vault with a new master password.
```
$ ./passman.exe change-master
Master password:
New master password:
Confirm new password:
master password changed
```

---

## Security

| What | How |
|------|-----|
| Encryption | AES-256-GCM |
| Key derivation | Argon2id (from master password + salt) |
| Storage | `data.json` (encrypted binary) |
| Salt | `.salt` (auto-created on first run) |
| Clipboard | Password copied, auto-clears after 30s |
| Brute-force protection | Vault locks for 5 min after 5 wrong attempts |

---

## Important

- **Back up both `data.json` and `.salt`** — losing `.salt` means you cannot decrypt your vault, even with the correct master password.
- If you forget your master password, there is no recovery.
- `data.json` from v1 (plaintext) is not compatible — re-add entries after upgrading.

---

## Roadmap

See [PLAN.md](PLAN.md).

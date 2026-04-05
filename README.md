# passman

A minimal CLI password manager written in Go.

## What's built (v1)

Passwords are stored as plain JSON in `data.json` (local file, no external dependencies).

Each entry has three fields: `site`, `user`, `pass`.

### Commands

**Add a password**
```
go run main.go add <site> <user> <password>
```

**Get a password**
```
go run main.go get <site>
```

### Example

```
$ go run main.go add github jyotir myPass123
added

$ go run main.go get github
jyotir myPass123
```

## Storage format

`data.json` — a JSON array of entries:
```json
[
  {
    "site": "google",
    "user": "user@gmail.com",
    "pass": "myPass@123"
  }
]
```

## Planned

- Encryption for stored passwords
- Delete / list commands

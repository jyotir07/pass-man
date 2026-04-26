package main

import (
	"fmt"
	"os"
	"strconv"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		return
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	// gen doesn't touch the vault, so skip unlocking.
	if cmd == "gen" {
		length := 16
		if len(args) >= 1 {
			length, _ = strconv.Atoi(args[0])
			if length <= 0 {
				length = 16
			}
		}
		fmt.Println(genPass(length))
		return
	}

	checkLock()

	salt, err := getOrCreateSalt()
	if err != nil {
		fmt.Printf("salt error: %s\n", err)
		os.Exit(1)
	}
	pass := promptPass("Master password: ")
	key := deriveKey(pass, salt)

	vault, err := loadVault(key)
	if err != nil {
		recordFailure()
		os.Exit(1)
	}
	resetLock()

	runCommand(cmd, args, vault, key, salt)
}

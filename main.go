package main

import (
	"encoding/json"
	"fmt"
	"os"
)

type E struct {
	S string `json:"site"`
	U string `json:"user"`
	P string `json:"pass"`
}

func ld() []E {
	f, _ := os.ReadFile("data.json")
	var a []E
	json.Unmarshal(f, &a)
	return a
}

func sv(a []E) {
	b, _ := json.MarshalIndent(a, "", " ")
	os.WriteFile("data.json", b, 0644)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("use: add/get")
		return
	}

	cmd := os.Args[1]
	a := ld()

	if cmd == "add" {
		if len(os.Args) < 5 {
			fmt.Println("add site user pass")
			return
		}
		e := E{os.Args[2], os.Args[3], os.Args[4]}
		a = append(a, e)
		sv(a)
		fmt.Println("added")
	} else if cmd == "get" {
		if len(os.Args) < 3 {
			fmt.Println("get site")
			return
		}
		for _, e := range a {
			if e.S == os.Args[2] {
				fmt.Println(e.U, e.P)
				return
			}
		}
		fmt.Println("not found")
	}
}
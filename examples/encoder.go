package main

import (
	"fmt"
	"os"

	dis "github.com/whyrusleeping/DissidentGo"
)

func main() {
	if len(os.Args) < 4 || len(os.Args) % 2 == 0 {
		fmt.Println("Not enough or invalid number of arguments!")
		fmt.Printf("Usage: %s plaintextfile type key message [key2 message2] ...\n", os.Args[0])
		return
	}
	var pf dis.PrepFunc
	switch os.Args[2] {
		case "tab":
			pf = dis.TabCover
		case "comma":
			pf = dis.OxfordComma
		case "lineend":
			ps = dis.LineEnding
		default:
			fmt.Println("Invalid encoding type!")
			fmt.Println("Options are:")
			fmt.Println("tab, comma, lineend")
			return
	}
	inp, err := os.Open(os.Args[1])
	if err != nil {
		panic(err)
	}
	var messages []*dis.Message
	for i := 3; i < len(os.Args); i += 2 {
		messages = append(messages, dis.MakeMessage(os.Args[i], os.Args[i+1]))
	}
	dis.Encode(inp, os.Stdout, messages, pf)
}

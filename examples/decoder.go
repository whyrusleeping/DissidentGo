package main

import (
	"fmt"
	"os"
	dis "github.com/whyrusleeping/DissidentGo"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Not enough arguments!")
		fmt.Printf("Usage: %s ciphertextfile key1 [key2] ...\n")
		return
	}
	in, err := os.Open(os.Args[1])
	if err != nil {
		panic(err)
	}

	for i := 2; i < len(os.Args); i++ {
		in.Seek(0, os.SEEK_SET)
		fmt.Println(string(dis.Decode(in, os.Args[i])))
	}
}

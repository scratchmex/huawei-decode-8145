//go:build !js

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
)

func main() {
	mode := flag.String("mode", "", "enc|dec")
	file := flag.String("file", "", "")

	flag.Parse()

	if flag.NFlag() != 2 {
		flag.PrintDefaults()
		os.Exit(1)
	}

	if flag.NArg() > 0 {
		log.Printf("unknown args: %s", flag.Args())
		os.Exit(1)
	}

	data, err := os.ReadFile(*file)
	if err != nil {
		log.Panicln("read file err:", err)
	}

	var output []byte
	switch *mode {
	case "enc":
		log.Println("encoding...")
		output = XmlEncode(data)
	case "dec":
		log.Println("decoding...")
		output = XmlDecode(data)
	}

	fmt.Print(string(output))
}

//go:build js

//go:generate cp $GOROOT/lib/wasm/wasm_exec.js .

package main

import (
	"fmt"
	"syscall/js"
)

func getBytesFromJs(v js.Value) []byte {
	size := v.Get("byteLength").Int()
	dst := make([]byte, size)
	js.CopyBytesToGo(dst, v)
	return dst
}

func withRecover() {
	if r := recover(); r != nil {
		fmt.Println("Recovered from panic", r)
	}
}

func main() {

	js.Global().Set("xmlEncode", js.FuncOf(func(this js.Value, args []js.Value) any {
		defer withRecover()
		input := getBytesFromJs(args[0])
		return string(XmlEncode(input))
	}))

	js.Global().Set("xmlDecode", js.FuncOf(func(this js.Value, args []js.Value) any {
		defer withRecover()
		input := getBytesFromJs(args[0])
		return string(XmlDecode(input))
	}))

	js.Global().Set("valueEncode", js.FuncOf(func(this js.Value, args []js.Value) any {
		defer withRecover()
		input := args[0].String()
		return input
	}))

	js.Global().Set("valueDecode", js.FuncOf(func(this js.Value, args []js.Value) any {
		defer withRecover()
		input := args[0].String()
		out := ValueDecode(input)
		return out
	}))

	select {}
}

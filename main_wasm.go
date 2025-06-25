//go:build js

//go:generate cp $GOROOT/lib/wasm/wasm_exec.js .

package main

import "syscall/js"

func getBytesFromJs(v js.Value) []byte {
	size := v.Get("byteLength").Int()
	dst := make([]byte, size)
	js.CopyBytesToGo(dst, v)
	return dst
}

func main() {
	js.Global().Set("encode", js.FuncOf(func(this js.Value, args []js.Value) any {
		input := getBytesFromJs(args[0])
		return string(encode(input))
	}))

	js.Global().Set("decode", js.FuncOf(func(this js.Value, args []js.Value) any {
		input := getBytesFromJs(args[0])
		return string(decode(input))
	}))

	select {}
}

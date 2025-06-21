//go:build js

//go:generate cp $GOROOT/lib/wasm/wasm_exec.js .

package main

import "syscall/js"

func main() {
	js.Global().Set("encode", js.FuncOf(func(this js.Value, args []js.Value) any {
		return string(encode([]byte(args[0].String())))
	}))

	document := js.Global().Get("document")

	fileInput := document.Call("getElementById", "fileInput")
	fileOutput := document.Call("getElementById", "fileOutput")

	fileInput.Set("oninput", js.FuncOf(func(v js.Value, x []js.Value) any {
		fileInput.Get("files").Call("item", 0).Call("arrayBuffer").Call("then", js.FuncOf(func(v js.Value, x []js.Value) any {
			data := js.Global().Get("Uint8Array").New(x[0])
			dst := make([]byte, data.Get("length").Int())
			js.CopyBytesToGo(dst, data)

			out := string(decode(dst))

			fileOutput.Set("innerText", out)

			return nil
		}))

		return nil
	}))

	select {}
}

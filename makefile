build-web:
	rm -rf buildweb
	mkdir buildweb
	GOOS=js GOARCH=wasm go build -o buildweb/main.wasm
	GOOS=js GOARCH=wasm go generate
	cp -a wasm_exec.js buildweb/
	cp -a index.html buildweb/

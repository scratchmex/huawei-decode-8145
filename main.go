package main

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"flag"
	"fmt"
	"hash/crc32"
	"io"
	"log"
	"os"
)

/*
the xml config file consists of

[0,   7] header
[8, ...] cipher text (gzip compressed, compress-then-encrypt)

## header
[0, 3]
[4, 8]


## ciphertext structure

[0,  15] IV
[16, 31] AES encrypted block 1
...
[    N*16,     N*16+15] AES encrypted block N
[(N+1)*16, (N+1)*16+31] HMAC-SHA256(plaintext)

the last 4 bits of the IV is the pad len
the pad content is taken from the IV

the HMAC is encrypt-then-mac

the AES key (mainkey) is obtained by composing sha256 func 8192 times with the previous value + the init key. the first value are 32 bytes in which the first 16 bytes is the IV
*/

var InitKey = []byte("hex:13395537D2730554A176799F6D56A239")
var DefaultName = "hw_tree.xml"

func encode(data []byte) []byte {
	compdatabuf := bytes.Buffer{}
	gzipw := gzip.NewWriter(&compdatabuf)
	if _, err := io.Copy(gzipw, bytes.NewReader(data)); err != nil {
		log.Panicln(err)
	}
	gzipw.Close()
	compdata := compdatabuf.Bytes()
	lenmod := len(compdata) % aes.BlockSize

	iv := getIv(uint(len(data)), DefaultName)

	iv[15] &= 0xF0
	iv[15] |= byte(lenmod)

	mainkey := getMainKey(iv)

	hmach := hmac.New(sha256.New, mainkey)
	cblock, err := aes.NewCipher(mainkey)
	if err != nil {
		log.Panicln("aes new cipher err:", err)
	}
	cblockm := cipher.NewCBCEncrypter(cblock, iv)

	dataplen := len(compdata)
	if lenmod > 0 {
		dataplen += 16 - lenmod
	}
	output := make([]byte, 8+16+dataplen+32)
	header := output[:8]
	ciphertext := output[8+16 : len(output)-32]

	for i := 0; i < len(compdata); i += aes.BlockSize {
		block := compdata[i:]
		if len(block) < aes.BlockSize {
			block = append(block, iv[lenmod:]...)
		} else {
			block = block[:aes.BlockSize]
		}

		dstblock := ciphertext[i : i+aes.BlockSize]
		cblockm.CryptBlocks(dstblock, block)
		hmach.Write(dstblock)
	}

	crch := crc32.New(&crc32_ccit_table)
	crch.Write([]byte(DefaultName))

	header[0] = 1
	binary.LittleEndian.PutUint32(header[4:8], crch.Sum32())

	copy(output[8:8+16], iv)
	copy(output[len(output)-32:], hmach.Sum(nil))

	return output
}

func decode(input []byte) []byte {
	// header := input[:8]
	iv := input[8 : 8+16]
	cipherdata := input[8+16 : len(input)-32]
	filehmac := input[len(input)-32:]
	lenmod := int(iv[15] & 0x0F)

	mainkey := getMainKey(iv)

	hmach := hmac.New(sha256.New, mainkey)
	cblock, err := aes.NewCipher(mainkey)
	if err != nil {
		log.Panicln("aes new cipher err:", err)
	}
	cblockm := cipher.NewCBCDecrypter(cblock, iv)

	compdata := make([]byte, len(cipherdata))

	for i := 0; i < len(compdata); i += aes.BlockSize {
		block := cipherdata[i : i+aes.BlockSize]
		dstblock := compdata[i : i+aes.BlockSize]

		hmach.Write(block)
		cblockm.CryptBlocks(dstblock, block)
	}

	if lenmod > 0 {
		compdata = compdata[:len(compdata)-(16-lenmod)]
	}

	if !hmac.Equal(hmach.Sum(nil), filehmac) {
		log.Panicln("hmac don't match")
	}

	// conttype := http.DetectContentType(compdata)
	// log.Printf("compadata detected as %s, first 32 bytes: %s", conttype, compdata[:32])

	outputbuf := bytes.Buffer{}
	gzipr, err := gzip.NewReader(bytes.NewReader(compdata))
	if err != nil {
		log.Panicln("gzip new reader err:", err)
	}
	gzipr.Multistream(false)
	if n, err := io.Copy(&outputbuf, gzipr); err != nil {
		log.Printf("gzip reading all (%d read) err: %s", n, err)
	}

	return outputbuf.Bytes()
}

// solely purpose to make it reproducable
// sha256(filesize + filename)[:16]
func getIv(size uint, name string) []byte {
	dig := sha256.New()
	binary.Write(dig, binary.BigEndian, size)
	dig.Write([]byte(name))

	return dig.Sum(nil)[:16]
}

func getMainKey(iv []byte) []byte {
	mainkey := make([]byte, 32)
	copy(mainkey[0:16], iv)

	keydig := sha256.New()
	for range 8192 {
		// log.Printf("digest %d: %x", i, mainkey)
		keydig.Write(mainkey)
		keydig.Write(InitKey)
		mainkey = keydig.Sum(nil)
		keydig.Reset()
	}
	return mainkey
}

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
		output = encode(data)
	case "dec":
		log.Println("decoding...")
		output = decode(data)
	}

	fmt.Print(string(output))
}

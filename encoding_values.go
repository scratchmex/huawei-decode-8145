package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"html"
	"log"
	"strings"
)

/*
encoding for values

mode 2 values are recognized because they are of the form `$2...$`
these values are AES_CBC enc with the key
sha256("9jK0lk5kLmxn8sjojW962llHY76xAc2zDf7!ui%s9(lmV1L8")

the values are html escaped

in addition, the values are have a custom ascii encoding `HW_AES_AscUnvisible` which maps
0x7e (char ~) <> 0x1e
and all other values are shifted by 0x21 (char !)

data is grouped in chunks of 5 bytes which are base-93 encoded and results in 4 bytes (uint32 little-endian).
that is

chunk  c1    c2     ...
idx    01234 01234  ...

where then you apply (in the case of decode)

f(c) = \sum_{i=0}^4 93^i * c[i]

to each chunk giving you 4 bytes (uint32 little endian)
the block size is 16, so each 20 bytes (4 chunks) maps to a block (16=20/5*4 bytes)
tl;dr: each 5 bytes is the base-93 representation of a uint32 (4 bytes) in little-endian


the IV is the last block of the data

data: <cipher text><IV>


the call tree for the decode is

HW_AESCBC_Decrypt
	string HTML unescape

	HW_AES_Trim: extracts $2<data>$

	HW_AES_AscUnvisible: "unescapes" <data ascii>

	HW_AES_PlainToBin: iterate in chunks of 5 bytes
		HW_AES_AesEnhSysToLong: decode 5 bytes in base-93 representation to 4 bytes

based on https://blog.fayaru.me/posts/huawei_router_config/
*/

// decodes the data from ascii to real bytes
func valueDecodeAscii(in string) []byte {
	s := html.UnescapeString(in)
	if len(s)%5 != 0 {
		log.Panic("input string len (html unescaped) is not multiple of 5")
	}

	b := []byte(s)
	// unescape ascii by shifting by 0x21 except if it's 0x7e (char ~)
	for i := range b {
		if b[i] == 0x7e {
			b[i] = 0x1e
		} else {
			b[i] -= 0x21
		}
	}

	newb := make([]byte, 0, len(b)/5*4)
	// decode chunks of 5 bytes in base-93 representation to chunks of 4 bytes
	for ci := range len(b) / 5 {
		c := b[5*ci : 5*ci+5]

		v := uint32(0)
		ex := 1
		for j := range c {
			v += uint32(ex * int(c[j]))
			ex *= 93
		}

		newb = binary.LittleEndian.AppendUint32(newb, v)
	}

	return newb
}

var XmlKey, _ = hex.DecodeString("6fc6e3436a53b6310dc09a475494ac774e7afb21b9e58fc8e58b5660e48e2498")

func ValueDecode(in string) string {
	if !strings.HasPrefix(in, "$2") {
		log.Panicln("string should start with $2")
	}
	input := valueDecodeAscii(in[2 : len(in)-1])
	bs := 16
	nblocks := len(input) / bs
	cipherdata := input[:bs*(nblocks-1)]
	iv := input[bs*(nblocks-1):]

	cblock, err := aes.NewCipher(XmlKey)
	if err != nil {
		log.Panicln("aes new cipher err:", err)
	}
	cblockm := cipher.NewCBCDecrypter(cblock, iv)

	outdata := make([]byte, len(cipherdata))
	for i := 0; i < len(outdata); i += aes.BlockSize {
		block := cipherdata[i : i+aes.BlockSize]
		dstblock := outdata[i : i+aes.BlockSize]

		cblockm.CryptBlocks(dstblock, block)
	}

	return strings.TrimRight(string(outdata), "\x00")
}

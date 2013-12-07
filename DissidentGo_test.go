package DissidentGo

import (
	"math/rand"
	"time"
	"bytes"
	"testing"
)

func randBytes(size int) []byte {
	b := make([]byte, size)
	for i,_ := range b {
		b[i] = byte(rand.Intn(256))
	}
	return b
}

func TestEncode(t *testing.T) {
	key := make([]byte, 16)
	for i,_ := range key {
		key[i] = 7
	}
	plaintext := []Text{Text{[]byte("abc"), [][]byte{[]byte{}, []byte("pqr")}}}
	for i := 0; i < 50; i++ {
		plaintext = append(plaintext, Text{randBytes(15), [][]byte{[]byte("ab"),[]byte("cde")}})
	}
	plaintext = append(plaintext, Text{[]byte("stuv"),nil})
	message := []byte("hey")
	enc := encodeMessages([]*Message{&Message{key, message}}, plaintext)
	if !bytes.Equal(message, partialDecodeMessages(key, enc, len(message))) {
		panic("encode failed")
	}
}

func TestCrypt(t *testing.T) {
	key := []byte("key")
	message := []byte("abc")
	mes := prepareMessage(&Message{key, message})
	plaintext := []Text{Text{[]byte("abc"), [][]byte{[]byte{}, []byte("pqr")}}}
	for i := 0; i < 100; i++ {
		plaintext = append(plaintext, Text{randBytes(15), [][]byte{[]byte("ab"), []byte("cde")}})
	}
	plaintext = append(plaintext, Text{[]byte("stuv"), nil})
	enc := packAndEncodeMessages([]*Message{mes}, plaintext)
	dec := decodeAndDecryptMessage(key, enc)
	if !bytes.Equal(dec, message) {
		panic("Encryption failed!")
	}
}

func TestSolve(t *testing.T) {
	rand.Seed(time.Now().UnixNano())
	vectors := make([][]byte, 10)
	for i,_ := range vectors {
		vectors[i] = make([]byte, 5)
		for j,_ := range vectors[i] {
			vectors[i][j] = byte(rand.Intn(2))
		}
	}
	goal := make([]byte, 5)
	for i,_ := range goal {
		goal[i] = byte(rand.Intn(2))
	}
	solution := solve(vectors,goal)
	tm := make([]byte, 5)
	for i,_ := range solution {
		if solution[i] != 0 {
			tm = xor(tm, vectors[i])
		}
	}
	if !bytes.Equal(tm,goal) {
		panic("SOLVE FAILED.")
	}
}

func TestEncrypt(t *testing.T) {
	key := []byte("abcdabcdabcdabcd")

	fullstr := make([]byte, 256)
	for i,_ := range(fullstr) {
		fullstr[i] = byte(i)
	}
	for i := 1; i < len(fullstr); i++ {
		mystr := fullstr[:i]
		if !bytes.Equal(mystr, decryptMessage(key, encryptMessage(key, mystr))) {
			panic("Encryption failed!!")
		}
	}
}


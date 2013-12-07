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
	if !bytes.Equal(message, partialDecodeMessage(key, enc, len(message))) {
		t.Fail()
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
		t.Fail()
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
		t.Fail()
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
			t.Fail()
		}
	}
}

func TestPack(t *testing.T) {
	fullstr := make([]byte, 256)
	for i,_ := range(fullstr) {
		fullstr[i] = byte(i)
	}
	for i := 4; i < len(fullstr); i++ {
		mystr := fullstr[:i]
		packed := packMessage(mystr)
		if beginUnpackMessage(packed) != len(packed) {
			t.Fail()
		}
		if !bytes.Equal(unpackMessage(packed), mystr) {
			t.Fail()
		}
	}
}

//Expected output:
//[b'a', [b'b', b'q'], b'cy']
//[b'xabc', [b'', b'd'], b'y']
//[b'x', [b'', b'd'], b'abcy']
//[b'xa', [b'', b'q'], b'cy']
func TestRemoveTooShort(t *testing.T) {
	input := []Text{Text{[]byte{}, [][]byte{[]byte("abc"),[]byte("aqc")}}, Text{[]byte("y"), nil}}
	out := removeTooShort(input)
	printTexts(out)
	ninput := []Text{Text{[]byte("x"), [][]byte{[]byte("abc"),[]byte("abcd")}}, Text{[]byte("y"), nil}}
	out = removeTooShort(ninput)
	printTexts(out)
	ninput = []Text{Text{[]byte("x"), [][]byte{[]byte("abc"),[]byte("dabc")}}, Text{[]byte("y"), nil}}
	out = removeTooShort(ninput)
	printTexts(out)
	ninput = []Text{Text{[]byte("x"), [][]byte{[]byte("ac"),[]byte("aqc")}}, Text{[]byte("y"), nil}}
	out = removeTooShort(ninput)
	printTexts(out)
}

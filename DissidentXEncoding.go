package main

import (
	"code.google.com/p/go.crypto/sha3"
	"fmt"
	"crypto/aes"
	"crypto/cipher"
	"bytes"
	"math/rand"
	"time"
)

func h(b []byte) []byte {
	hash := sha3.NewKeccak256()
	hash.Write(b)
	return hash.Sum(nil)
}

func x(m1 []byte, m2 []byte) []byte {
	if len(m2) > len(m1) {
		m1,m2 = m2,m1
	}
	ret := make([]byte, len(m1))
	for i := 1; i <= len(ret); i++ {
		if i > len(m2) {
			ret[len(ret) - i] = m1[len(m1) - i]
		} else {
			ret[len(ret) - i] = m1[len(m1) - i] ^ m2[len(m2) - i]
		}
	}
	return ret
}

func encryptAESCFB(dst, src, key, iv []byte) error {
	blockEncrypter, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	aesEncrypter := cipher.NewOFB(blockEncrypter, iv)
	aesEncrypter.XORKeyStream(dst, src)
	return nil
}

func decryptAESCFB(dst, src, key, iv []byte) error {
	blockEncrypter, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	aesDecrypter := cipher.NewOFB(blockEncrypter, iv)
	aesDecrypter.XORKeyStream(dst, src)
	return nil
}

func encryptOfb(key, iv, plaintext []byte) []byte {
	if len(key) != 16 {
		panic("Key too short!")
	}
	if len(iv) != 16 {
		panic("iv too short!")
	}
	msg := make([]byte, len(plaintext))
	err := encryptAESCFB(msg, plaintext, key, iv)
	if err != nil {
		panic(err)
	}
	return msg
}

func catBytes(a,b []byte) []byte {
	ret := make([]byte, len(a) + len(b))
	i := 0
	for _,v := range(a) {
		ret[i] = v
		i++
	}
	for _,v := range(b) {
		ret[i] = v
		i++
	}
	return ret
}

func encryptMessage(key, plaintext []byte) []byte {
	mac := h(catBytes(key, plaintext))[:4]
	iv := catBytes(mac, make([]byte, 12))
	return catBytes(mac, encryptOfb(key, iv, plaintext))
}

func prepareMessage(key, plaintext []byte) ([]byte, []byte) {
	key = h(key)[:16]
	return h(key)[:16], encryptMessage(key, plaintext)
}

func decryptMessage(key, ciphertext []byte) []byte {
	mac := ciphertext[:4]
	r := encryptOfb(key, catBytes(mac, make([]byte, 12)), ciphertext[4:])
	if bytes.Equal(mac, h(catBytes(key, r))[:4]) {
		return r
	}
	return nil
}

func testEncrypt() {
	key := []byte("abcdabcdabcdabcd")

	fullstr := make([]byte, 256)
	for i,_ := range(fullstr) {
		fullstr[i] = byte(i)
	}
	for i := 1; i < len(fullstr); i++ {
		mystr := fullstr[:i]
		if !bytes.Equal(mystr, decryptMessage(key, encryptMessage(key, mystr))) {
			fmt.Println("Encryption failed!!")
		}
	}
}

func packMessage(message []byte) []byte {
	if len(message) < 4 {
		panic("message not long enough! [len < 4]")
	}
	r := message[:4]
	v := len(message) - 4
	var lb []byte
	if v < 128 {
		lb = []byte{byte(v)}
	} else {
		lb = []byte{byte(128 | v >> 8),byte(v & 0xFF)}
	}

	r = catBytes(r, x(lb, h(r)[:len(lb)]))
	r = catBytes(r, h(r)[:2])
	return catBytes(r, message[4:])
}

func beginUnpackMessage(message []byte) int {
	var mlen int
	var mbegin int
	prefix := x(h(message[:4])[:2], message[4:6])
	if prefix[0] < 128 {
		mlen = int(prefix[0] + 4)
		mbegin = 5
	} else {
		mlen = ((int(prefix[0] - 128) << 8) | int(prefix[1])) + 4
		mbegin = 6
	}
	if !bytes.Equal(message[mbegin:mbegin+2], h(message[:mbegin])[:2]) {
		return -1
	}
	return mlen + mbegin - 2
}

func unpackMessage(message []byte) []byte {
	var mlen int
	var mbegin int
	prefix := x(h(message[:4])[:2], message[4:6])
	if prefix[0] < 128 {
		mlen = int(prefix[0] + 4)
		mbegin = 5
	} else {
		mlen = ((int(prefix[0] - 128) << 8) | int(prefix[1])) + 4
		mbegin = 6
	}
	if len(message) != mlen + mbegin - 2 {
		panic("Message length does not match!")
	}
	return catBytes(message[:4], message[mbegin + 2:])
}

func testPack() {

	fullstr := make([]byte, 256)
	for i,_ := range(fullstr) {
		fullstr[i] = byte(i)
	}
	for i := 4; i < len(fullstr); i++ {
		mystr := fullstr[:i]
		packed := packMessage(mystr)
		if beginUnpackMessage(packed) != len(packed) {
			panic("Failed to pack!")
		}
		if !bytes.Equal(unpackMessage(packed), mystr) {
			panic("Failed to unpack!")
		}
	}
}

type Text struct {
	first []byte
	sec [][]byte
}

func (t Text) Print() {
	fmt.Printf("'%s', [",string(t.first))
	for _,v := range t.sec {
		fmt.Printf("'%s' ", string(v))
	}
	fmt.Print("], ")
}

func removeTooShort(plaintext []Text) []Text {
	p2 := []Text{Text{[]byte{}, nil}}
	for i := 0; i < len(plaintext) - 1; i++ {
		printTexts(p2)
		printTexts(plaintext)
		p2[len(p2) - 1].first = catBytes(p2[len(p2) - 1].first, plaintext[i].first)

		if len(p2) > 1 && len(p2[len(p2) - 1].sec) < 15 {
			fmt.Println("There.")
			p2[len(p2) - 1].first = catBytes(p2[len(p2) - 1].first, plaintext[i].sec[0])
		} else {
			a,b := plaintext[i].sec[0], plaintext[i].sec[1]
			fmt.Printf("a,b:\n")
			fmt.Println(string(a))
			fmt.Println(string(b))
			var j int
			for j = 0; j < len(a) && j < len(b) && a[j] == b[j]; j++ {}
			if j > 0 {
				fmt.Printf("j > 0! [%d]\n", j)
				p2[len(p2) - 1].first = catBytes(p2[len(p2)-1].first, a[:j])
				a = a[j:]
				b = b[j:]
			}
			fmt.Printf("a,b: (after)\n")
			fmt.Println(string(a))
			fmt.Println(string(b))
			var excess []byte
			for j = 0; j<len(a) && j<len(b) &&
				a[len(a)-(j+1)] == b[len(b)-(j+1)]; j++ {}
			if j > 0 {
				fmt.Println("Here")
				excess = a[len(a)-j:]
				a = a[:len(a)-j]
				b = b[:len(b)-j]
			}
			fmt.Println("a,b,(excess)")
			fmt.Println(string(a))
			fmt.Println(string(b))
			fmt.Println(string(excess))
			p2[len(p2)-1].sec = [][]byte{a,b}
			p2 = append(p2, Text{excess,nil})
			printTexts(p2)
		}
	}
	p2[len(p2)-1].first = catBytes(p2[len(p2)-1].first, plaintext[len(plaintext)-1].first)
	return p2
}
func printTexts(t []Text) {
	fmt.Print("[")
	for _,v := range t {
		v.Print()
	}
	fmt.Println("]")
}

func testRemoveTooShort() {
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

func toBitfield(m []byte) []byte {
	var r []byte
	for _,v := range m {
		for i := byte(0); i < 8; i++ {
			r = append(r, (v >> i) & 1)
		}
	}
	return r
}

type Message struct {
	Key []byte
	Mes []byte
}

func partialDecodeMessages(key, mes []byte, mylen int) []byte {
	r := make([]byte, mylen)
	blank := make([]byte, mylen)
	for i := 0; i < len(mes) - 15; i++ {
		r = x(r, encryptOfb(key, mes[i:i+16], blank))
	}
	return r
}

func pdms(messages []*Message, text []byte) []byte {
	buf := new(bytes.Buffer)
	for _,m := range messages {
		buf.Write(partialDecodeMessages(m.Key, text, len(m.Mes)))
	}
	return buf.Bytes()
}

func encodeMessages(messages []*Message, plaintext []Text) []byte {
	plaintext = removeTooShort(plaintext)
	base := [][]byte{plaintext[0].first}
	for i := 0; i < len(plaintext); i++ {
		base = append(base,plaintext[i].sec[0])
		base = append(base, plaintext[i+1].first)
	}
	buf := new(bytes.Buffer)
	for _,m := range messages {
		buf.Write(m.Mes)
	}
	textbuf := new(bytes.Buffer)
	for _,v := range base {
		textbuf.Write(v)
	}
	goal := toBitfield(x(buf.Bytes(),pdms(messages, textbuf.Bytes())))
	var vectors [][]byte
	for i := 0; i < len(plaintext)-1; i++ {
		a := plaintext[i].first
		a = a[len(a)-15:]
		arg1 := catBytes(a, plaintext[i].sec[0])
		b := plaintext[i+1].first[:15]
		arg1 = catBytes(arg1, b)

		arg2 := catBytes(a, plaintext[i].sec[1])
		arg2 = catBytes(arg2, b)

		pdm1 := pdms(messages, arg1)
		pdm2 := pdms(messages, arg2)

		vectors = append(vectors, toBitfield(x(pdm1, pdm2)))
	}
	toflips := solve(vectors, goal)
	if toflips == nil {
		return nil
	}
	buf = new(bytes.Buffer)
	buf.Write(plaintext[0].first)
	for i := 0; i < len(plaintext)-1; i++ {
		buf.Write(plaintext[i].sec[toflips[i]])
		buf.Write(plaintext[i+1].first)
	}
	return buf.Bytes()
}

func packAndEncodeMessages(messages []*Message, plaintext []Text) []byte {
	out := make([]*Message, len(messages))
	for i,v := range messages {
		out[i] = &Message{v.Key, packMessage(v.Mes)}
	}
	return encodeMessages(out, plaintext)
}

func xor(a,b []byte) []byte{
	ret := make([]byte, len(a))
	for i,v := range a {
		ret[i] = v ^ b[i]
	}
	return ret
}

//Im fairly certain that this is a matrix operation of some sort
func solve(vectors [][]byte, goal []byte) []byte {
	var active [][]byte
	extra := make([]byte, len(vectors))
	for i,_ := range vectors {
		active = append(active, catBytes(vectors[i], extra))
	}
	for i := 0; i < len(active); i++ {
		active[i][len(goal) + i] = 1
	}
	for i := 0; i < len(goal); i++ {
		p := i
		for ;p < len(active) && active[p][i] == 0; p++ {}
		if p == len(vectors) {
			return nil
		}
		active[p], active[i] = active[i], active[p]
		for j := 0; j < len(active); j++ {
			if j != i && active[j][i] != 0 {
				active[j] = xor(active[j], active[i])
			}
		}
	}
	r := make([]byte, len(active))
	for i := 0; i < len(goal); i++ {
		if goal[i] != 0 {
			r = xor(r, active[i][len(goal):])
		}
	}
	return r
}

func testSolve() {
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
	t := make([]byte, 5)
	for i,_ := range solution {
		if solution[i] != 0 {
			t = xor(t, vectors[i])
		}
	}
	if !bytes.Equal(t,goal) {
		panic("SOLVE FAILED.")
	}
}

func main() {
	fmt.Println("TESTING:")
	testRemoveTooShort()
	testSolve()
}


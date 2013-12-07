package DissidentGo

import (
	"code.google.com/p/go.crypto/sha3"
	"fmt"
	"crypto/aes"
	"crypto/cipher"
	"bytes"
)

//A message to encode paired with the key to
//encode it with
type Message struct {
	Key []byte
	Mes []byte
}

//A struct used to represent an option for storing information
//in a stream of data.
//data: the part of the original data that will not be changed
//bit: a set of 'alternatives' that can be swapped in order to
//     actually embed your data into the plaintext
//
//This struct is always used in an array to the following effect:
// [data] [bit:a/b] [data] [bit:a/b] [data] [nil]
type Text struct {
	data []byte
	bit [][]byte
}

//returns a sha3 hash of the bytes
func h(b []byte) []byte {
	hash := sha3.NewKeccak256()
	hash.Write(b)
	return hash.Sum(nil)
}

//returns an xor of the bytes, does not require
//arrays to be same length
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

//Encrypt the 'src' bytes using AES OFB block encryption
func encryptAESOFB(dst, src, key, iv []byte) error {
	blockEncrypter, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	aesEncrypter := cipher.NewOFB(blockEncrypter, iv)
	aesEncrypter.XORKeyStream(dst, src)
	return nil
}

func decryptAESOFB(dst, src, key, iv []byte) error {
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
	err := encryptAESOFB(msg, plaintext, key, iv)
	if err != nil {
		panic(err)
	}
	return msg
}

//Concatenate two arrays of bytes
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

//Encrypt some text with a key
func encryptMessage(key, plaintext []byte) []byte {
	mac := h(catBytes(key, plaintext))[:4]
	iv := catBytes(mac, make([]byte, 12))
	return catBytes(mac, encryptOfb(key, iv, plaintext))
}

func prepareMessage(m *Message) *Message {
	key := h(m.Key)[:16]
	return &Message{h(key)[:16], encryptMessage(key, m.Mes)}
}

func decryptMessage(key, ciphertext []byte) []byte {
	mac := ciphertext[:4]
	r := encryptOfb(key, catBytes(mac, make([]byte, 12)), ciphertext[4:])
	if bytes.Equal(mac, h(catBytes(key, r))[:4]) {
		return r
	}
	return nil
}

//Embed the length of a message and a 'checksum' into
//a given message
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

//Extract the length of the message from the given bytes
//and verify the small checksum embedded along with it
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

//Get the original message from a packed message
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


func (t Text) Print() {
	fmt.Printf("'%s', [",string(t.data))
	for _,v := range t.bit {
		fmt.Printf("'%s' ", string(v))
	}
	fmt.Print("], ")
}

//Reduction of input data, conserves number of bytes needed to
//store messages
func removeTooShort(plaintext []Text) []Text {
	p2 := []Text{Text{[]byte{}, nil}}
	for i := 0; i < len(plaintext) - 1; i++ {
		p2[len(p2) - 1].data = catBytes(p2[len(p2) - 1].data, plaintext[i].data)

		if len(p2) > 1 && len(p2[len(p2) - 1].data) < 15 {
			p2[len(p2) - 1].data = catBytes(p2[len(p2) - 1].data, plaintext[i].bit[0])
		} else {
			a,b := plaintext[i].bit[0], plaintext[i].bit[1]
			var j int
			for j = 0; j < len(a) && j < len(b) && a[j] == b[j]; j++ {}
			if j > 0 {
				p2[len(p2) - 1].data = catBytes(p2[len(p2)-1].data, a[:j])
				a = a[j:]
				b = b[j:]
			}
			var excess []byte
			for j = 0; j<len(a) && j<len(b) &&
				a[len(a)-(j+1)] == b[len(b)-(j+1)]; j++ {}
			if j > 0 {
				excess = a[len(a)-j:]
				a = a[:len(a)-j]
				b = b[:len(b)-j]
			}
			p2[len(p2)-1].bit = [][]byte{a,b}
			p2 = append(p2, Text{excess,nil})
		}
	}
	p2[len(p2)-1].data = catBytes(p2[len(p2)-1].data, plaintext[len(plaintext)-1].data)
	return p2
}

func printTexts(t []Text) {
	fmt.Print("[")
	for _,v := range t {
		v.Print()
	}
	fmt.Println("]")
}

//Easier than bit shifting... honestly.
func toBitfield(m []byte) []byte {
	var r []byte
	for _,v := range m {
		for i := byte(0); i < 8; i++ {
			r = append(r, (v >> i) & 1)
		}
	}
	return r
}

func partialDecodeMessage(key, mes []byte, mylen int) []byte {
	r := make([]byte, mylen)
	blank := make([]byte, mylen)
	for i := 0; i < len(mes) - 15; i++ {
		r = x(r, encryptOfb(key, mes[i:i+16], blank))
	}
	return r
}

//Partially Decode Messages
func pdms(messages []*Message, text []byte) []byte {
	buf := new(bytes.Buffer)
	for _,m := range messages {
		buf.Write(partialDecodeMessage(m.Key, text, len(m.Mes)))
	}
	return buf.Bytes()
}

//Encode the given messages into the plaintext and return the
//modified text/data
func encodeMessages(messages []*Message, plaintext []Text) []byte {
	plaintext = removeTooShort(plaintext)
	base := [][]byte{plaintext[0].data}
	for i := 0; i < len(plaintext) - 1; i++ {
		base = append(base,plaintext[i].bit[0])
		base = append(base, plaintext[i+1].data)
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
		a := plaintext[i].data
		if len(a) > 15 {
			a = a[len(a)-15:]
		}
		arg1 := catBytes(a, plaintext[i].bit[0])
		b := plaintext[i+1].data
		if len(b) > 15 {
			b = b[:15]
		}
		arg1 = catBytes(arg1, b)

		arg2 := catBytes(a, plaintext[i].bit[1])
		arg2 = catBytes(arg2, b)

		pdm1 := pdms(messages, arg1)
		pdm2 := pdms(messages, arg2)

		vectors = append(vectors, toBitfield(x(pdm1, pdm2)))
	}
	toflips := solve(vectors, goal)
	if toflips == nil {
		fmt.Println("Solve failed! (most likely not enough plaintext)")
		return nil
	}
	buf = new(bytes.Buffer)
	buf.Write(plaintext[0].data)
	for i := 0; i < len(plaintext)-1; i++ {
		buf.Write(plaintext[i].bit[toflips[i]])
		buf.Write(plaintext[i+1].data)
	}
	return buf.Bytes()
}

func decodeAndDecryptMessage(key []byte, message []byte) []byte {
	key = h(key)[:16]
	key2 := h(key)[:16]

	mystr := partialDecodeMessage(key2, message, 16)
	mylen := beginUnpackMessage(mystr)

	if mylen == -1 {
		return nil
	}
	mystr = partialDecodeMessage(key2, message, mylen)
	if mystr == nil {
		return nil
	}
	mystr = unpackMessage(mystr)
	if mystr == nil {
		return nil
	}
	return decryptMessage(key, mystr)
}

func packAndEncodeMessages(messages []*Message, plaintext []Text) []byte {
	out := make([]*Message, len(messages))
	for i,v := range messages {
		out[i] = &Message{v.Key, packMessage(v.Mes)}
	}
	return encodeMessages(out, plaintext)
}

//XOR of bytes (same length arrays)
func xor(a,b []byte) []byte{
	ret := make([]byte, len(a))
	for i,v := range a {
		ret[i] = v ^ b[i]
	}
	return ret
}

//Im fairly certain that this is a matrix operation of some sort
//I didnt write this code, but if you have a good insight
//about what it is doing. please teach me!
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

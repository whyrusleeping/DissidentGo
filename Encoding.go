package DissidentGo

import (
	"bytes"
	"io"
	"io/ioutil"
	"fmt"
)

func Decode(in io.Reader, key string) []byte {
	p, err := ioutil.ReadAll(in)
	if err != nil {
		panic(err)
	}

	return decodeAndDecryptMessage([]byte(key), p)
}

type PrepFunc func([]byte) []Text
func Encode(in io.Reader, out io.Writer, m []*Message, prep PrepFunc) {
	ptext, err := ioutil.ReadAll(in)
	if err != nil {
		panic(err)
	}
	prepm := make([]*Message, len(m))
	for i := 0; i < len(m); i++ {
		prepm[i] = prepareMessage(m[i])
	}
	mout := packAndEncodeMessages(prepm, prep(ptext))

	_,err = out.Write(mout)
	if err != nil {
		panic(err)
	}
}

//Encode the message in the usage of tabs versus spaces
var nlByte = []byte("\n")
//var etSpace = []byte("        ")
var etSpace = []byte("    ")
var tabByte = []byte("\t")
func TabCover(in []byte) []Text {
	var ct []Text
	for _,v := range bytes.Split(in, nlByte) {
		if len(ct) > 0 {
			ct[len(ct)-1].data = catBytes(ct[len(ct)-1].data, nlByte)
		} else {
			ct = []Text{Text{[]byte{}, nil}}
		}
		if len(v) > 0 && v[0] == '\t' {
			var p int
			ntab := bytes.NewBuffer(tabByte)
			nspace := bytes.NewBuffer(etSpace)
			for p = 1; v[p] == '\t'; p++ {
				ntab.Write(tabByte)
				nspace.Write(etSpace)
			}
			ct[len(ct)-1].bit = [][]byte{ntab.Bytes(),nspace.Bytes()}
			ct = append(ct, Text{v[p:],nil})
		} else if len(v) > 7 && bytes.Equal(v[:8], etSpace) {
			p := 1
			ntab := bytes.NewBuffer(tabByte)
			nspace := bytes.NewBuffer(etSpace)
			for ;bytes.Equal(v[p*8:(p+1)*8], etSpace);p++ {
				ntab.Write(tabByte)
				nspace.Write(etSpace)
			}
			ct[len(ct)-1].bit = [][]byte{nspace.Bytes(),ntab.Bytes()}
			ct = append(ct, Text{v[p*8:],nil})
		} else {
			ct[len(ct)-1].data = catBytes(ct[len(ct)-1].data, v)
		}
	}
	return ct
}

//Encode the message in the alternating of the usage
//of oxford commas
var com = []byte(", and")
var ncom = []byte(" and")
func OxfordComma(in []byte) []Text {
	var r []Text
	swap := [][]byte{com,ncom}
	for _,v := range bytes.Split(in, com) {
		if len(r) > 0 {
			r[len(r)-1].bit = swap
		}
		r = append(r, Text{v, nil})
	}
	return r
}

var spnlByte = []byte(" \n")
func LineEnding(in []byte) []Text {
	var r []Text
	swap := [][]byte{nlByte, spnlByte}
	for _,v := range bytes.Split(in, nlByte) {
		if len(r) > 0 {
			r[len(r)-1].bit = swap
		}
		r = append(r, Text{v, nil})
	}
	return r
}

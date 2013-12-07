package DissidentGo

import (
	"bytes"
	"io"
	"io/ioutil"
)

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

var nlByte = []byte("\n")
var etSpace = []byte("        ")
var tabByte = []byte("\t")
func TabCover(in []byte) []Text {
	var ct []Text
	for _,v := range bytes.Split(in, nlByte) {
		if len(ct) > 0 {
			ct[len(ct)-1].first = catBytes(ct[len(ct)-1].first, nlByte)
		} else {
			ct = []Text{Text{[]byte{}, nil}}
		}
		if v[0] == '\t' {
			var p int
			ntab := new(bytes.Buffer)
			nspace := new(bytes.Buffer)
			for p = 1; v[p] == '\t'; p++ {
				ntab.Write(tabByte)
				nspace.Write(etSpace)
			}
			ct[len(ct)-1].sec = [][]byte{ntab.Bytes(),nspace.Bytes()}
			ct = append(ct, Text{v[p:],nil})
		} else if bytes.Equal(v[:8], etSpace) {
			p := 1
			ntab := new(bytes.Buffer)
			nspace := new(bytes.Buffer)
			for ;bytes.Equal(v[p*8:(p+1)*8], etSpace);p++ {
				ntab.Write(tabByte)
				nspace.Write(etSpace)
			}
			ct[len(ct)-1].sec = [][]byte{nspace.Bytes(),ntab.Bytes()}
			ct = append(ct, Text{v[p*8:],nil})
		} else {
			ct[len(ct)-1].first = catBytes(ct[len(ct)-1].first, v)
		}
	}
	return ct
}

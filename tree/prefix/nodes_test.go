package prefix

import (
	"bytes"
	"testing"

	"github.com/Bren2010/katie/crypto/suites"
)

func makeBytes(b byte) []byte {
	out := make([]byte, 32)
	for i := range len(out) {
		out[i] = b
	}
	return out
}

func TestMarshalUnmarshal1(t *testing.T) {
	cs := suites.KTSha256P256{}
	n1 := &parentNode{
		left: &parentNode{
			left:  leafNode{makeBytes(1), makeBytes(2)},
			right: leafNode{makeBytes(3), makeBytes(4)},
		},
		right: leafNode{makeBytes(5), makeBytes(6)},
	}

	buf := &bytes.Buffer{}
	if err := n1.Marshal(cs, 0, buf); err != nil {
		t.Fatal(err)
	}
	n2, err := unmarshalNode(cs, nil, 0, bytes.NewBuffer(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}

	if got, want := n2.String(), n1.String(); got != want {
		t.Fatal("unmarshalled value incorrectly")
	}
}

func TestMarshalUnmarshal2(t *testing.T) {
	cs := suites.KTSha256P256{}
	n1 := &parentNode{
		left: leafNode{makeBytes(1), makeBytes(2)},
		right: &parentNode{
			left:  leafNode{makeBytes(3), makeBytes(4)},
			right: leafNode{makeBytes(5), makeBytes(6)},
		},
	}

	buf := &bytes.Buffer{}
	if err := n1.Marshal(cs, 0, buf); err != nil {
		t.Fatal(err)
	}
	n2, err := unmarshalNode(cs, nil, 0, bytes.NewBuffer(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}

	if got, want := n2.String(), n1.String(); got != want {
		t.Fatal("unmarshalled value incorrectly")
	}
}

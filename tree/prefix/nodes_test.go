package prefix

import (
	"bytes"
	"testing"
)

func TestMarshalUnmarshal1(t *testing.T) {
	n1 := parentNode{
		left: parentNode{
			left:  leafNode{[32]byte{1}, [32]byte{2}},
			right: leafNode{[32]byte{3}, [32]byte{4}},
		},
		right: leafNode{[32]byte{5}, [32]byte{6}},
	}

	buf := &bytes.Buffer{}
	if err := n1.Marshal(buf); err != nil {
		t.Fatal(err)
	}
	n2, err := unmarshalNode(bytes.NewBuffer(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}

	if got, want := n2.String(), n1.String(); got != want {
		t.Fatal("unmarshalled value incorrectly")
	}
}

func TestMarshalUnmarshal2(t *testing.T) {
	n1 := parentNode{
		left: leafNode{[32]byte{1}, [32]byte{2}},
		right: parentNode{
			left:  leafNode{[32]byte{3}, [32]byte{4}},
			right: leafNode{[32]byte{5}, [32]byte{6}},
		},
	}

	buf := &bytes.Buffer{}
	if err := n1.Marshal(buf); err != nil {
		t.Fatal(err)
	}
	n2, err := unmarshalNode(bytes.NewBuffer(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}

	t.Log(buf.Len() - (32 * 6))
	if got, want := n2.String(), n1.String(); got != want {
		t.Fatal("unmarshalled value incorrectly")
	}
}

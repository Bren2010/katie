package p256

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"testing"
)

func TestBlah(t *testing.T) {
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.PublicKey().Bytes()
	fmt.Printf("%x\n", pub)
	fmt.Println(len(pub))
}

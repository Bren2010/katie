// Command generate-keys outputs fresh cryptographic keys for a Katie Server.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"

	"github.com/SkewPrivacy/katie/crypto/vrf/p256"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	fmt.Println()

	signingKey := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(signingKey); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Signing Key:\n%x\n\n", signingKey)

	vrfPriv, _ := p256.GenerateKey()
	raw, err := x509.MarshalECPrivateKey(vrfPriv.(*p256.PrivateKey).PrivateKey)
	if err != nil {
		log.Fatal(err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{
		Type:  "VRF PRIVATE KEY",
		Bytes: raw,
	})
	fmt.Printf("VRF Private Key:\n%s\n", encoded)
}

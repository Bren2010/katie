// Command generate-keys outputs fresh cryptographic keys.
package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"flag"
	"fmt"
	"log"

	"github.com/Bren2010/katie/crypto/vrf/p256"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	flag.Parse()
	switch flag.Arg(0) {
	case "p256":
		generateP256()
	case "ed25519":
		generateEd25519()
	default:
		log.Fatalf("Usage: generate-keys (p256|ed25519)")
	}
}

func generateP256() {
	sigKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	sigKeyRaw, err := sigKey.Bytes()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Signing Private Key: %x\n", sigKeyRaw)

	sigPublic, err := sigKey.Public().(*ecdsa.PublicKey).Bytes()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Signing Public Key:  %x\n", sigPublic)

	vrfKey := p256.GeneratePrivateKey()
	fmt.Printf("VRF Private Key:     %x\n", vrfKey)

	temp, err := p256.NewPrivateKey(vrfKey)
	if err != nil {
		log.Fatal(err)
	}
	vrfPublic := temp.PublicKey().Bytes()
	fmt.Printf("VRF Public Key:      %x\n", vrfPublic)
}

func generateEd25519() {
	sigKey := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(sigKey); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Signing Private Key: %x\n", sigKey)

	sigPublic := ed25519.NewKeyFromSeed(sigKey).Public().(ed25519.PublicKey)
	fmt.Printf("Signing Public Key:  %x\n", sigPublic)

	vrfKey := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(vrfKey); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("VRF Private Key:     %x\n", vrfKey)

	vrfPublic := ed25519.NewKeyFromSeed(vrfKey).Public().(ed25519.PublicKey)
	fmt.Printf("VRF Public Key:      %x\n", vrfPublic)
}

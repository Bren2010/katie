// Command generate-keys outputs fresh cryptographic keys.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"log"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	sigKey := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(sigKey); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Signing Private Key: %x\n", sigKey)

	vrfKey := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(vrfKey); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("VRF Private Key:     %x\n", vrfKey)
}

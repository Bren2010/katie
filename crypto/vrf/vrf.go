// Package vrf defines the interface to a Verifiable Random Function.
package vrf

// PrivateKey represents a VRF private key.
type PrivateKey interface {
	Prove(m []byte) (index [32]byte, proof []byte)
	PublicKey() PublicKey
}

// PublicKey represents a VRF public key.
type PublicKey interface {
	Verify(m, proof []byte) (index [32]byte, err error)
}

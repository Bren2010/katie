// Package suites implements each supported cipher suite.
package suites

import (
	"hash"

	"github.com/Bren2010/katie/crypto/vrf"
)

// CipherSuite is the interface implemented by each supported cipher suite.
type CipherSuite interface {
	Id() uint16
	Hash() hash.Hash
	CommitmentOpeningSize() int
	CommitmentFixedBytes() []byte

	ParseSigningPrivateKey(raw []byte) (SigningPrivateKey, error)
	ParseSigningPublicKey(raw []byte) (SigningPublicKey, error)

	ParseVRFPrivateKey(raw []byte) (vrf.PrivateKey, error)
	ParseVRFPublicKey(raw []byte) (vrf.PublicKey, error)
}

// SigningPrivateKey is the interface implemented by signature private keys.
type SigningPrivateKey interface {
	Public() ([]byte, error)
	Sign(message []byte) ([]byte, error)
}

// SigningPublicKey is the interface implemented by signature public keys.
type SigningPublicKey interface {
	Verify(message, sig []byte) bool
}

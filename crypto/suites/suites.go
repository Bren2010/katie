// Package suites implements each supported cipher suite.
package suites

import (
	"hash"

	"github.com/Bren2010/katie/crypto/vrf"
)

// CipherSuite is the interface implemented by each supported cipher suite.
//
// All of the methods that start with "Parse" expect their input to come from
// locally stored configuration. This may differ from how the same values are
// serialized for use in the protocol.
type CipherSuite interface {
	Id() uint16
	Hash() hash.Hash
	HashSize() int
	CommitmentOpeningSize() int
	CommitmentFixedBytes() []byte
	VrfProofSize() int

	ParseSigningPrivateKey(raw []byte) (SigningPrivateKey, error)
	ParseSigningPublicKey(raw []byte) (SigningPublicKey, error)

	ParseVRFPrivateKey(raw []byte) (vrf.PrivateKey, error)
	ParseVRFPublicKey(raw []byte) (vrf.PublicKey, error)
}

// SigningPrivateKey is the interface implemented by signature private keys.
type SigningPrivateKey interface {
	Sign(message []byte) ([]byte, error)
	Public() SigningPublicKey
}

// SigningPublicKey is the interface implemented by signature public keys.
type SigningPublicKey interface {
	Verify(message, sig []byte) bool
	// Bytes returns the encoded public key, following protocol rules.
	Bytes() []byte
}

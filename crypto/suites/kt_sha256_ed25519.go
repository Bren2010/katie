package suites

import (
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"

	"github.com/Bren2010/katie/crypto/vrf"
)

// KTSha256Ed25519 implements the KT cipher suite using SHA-256 for hashing and
// ed25519 for signatures and the VRF.
type KTSha256Ed25519 struct{}

var _ CipherSuite = KTSha256Ed25519{}

func (s KTSha256Ed25519) Id() uint16       { return 0x02 }
func (s KTSha256Ed25519) Hash() hash.Hash  { return sha256.New() }
func (s KTSha256Ed25519) OpeningSize() int { return 16 }

func (s KTSha256Ed25519) CommitmentBytes() []byte {
	return []byte{
		0xd8, 0x21, 0xf8, 0x79, 0x0d, 0x97, 0x70, 0x97,
		0x96, 0xb4, 0xd7, 0x90, 0x33, 0x57, 0xc3, 0xf5,
	}
}

func (s KTSha256Ed25519) ParseSigningPrivateKey(raw []byte) (SigningPrivateKey, error) {
	decoded := make([]byte, hex.DecodedLen(len(raw)))
	n, err := hex.Decode(decoded, raw)
	if err != nil {
		return nil, err
	} else if n != len(decoded) {
		return nil, fmt.Errorf("unexpected number of bytes decoded")
	}
	return ed25519PrivateKey{ed25519.NewKeyFromSeed(decoded)}, nil
}

func (s KTSha256Ed25519) ParseSigningPublicKey(raw []byte) (SigningPublicKey, error) {
	if len(raw) != 2*ed25519.PublicKeySize {
		return nil, fmt.Errorf("encoded public key is unexpected size")
	}
	decoded := make([]byte, ed25519.PublicKeySize)
	n, err := hex.Decode(decoded, raw)
	if err != nil {
		return nil, err
	} else if n != len(decoded) {
		return nil, fmt.Errorf("unexpected number of bytes decoded")
	}
	return ed25519PublicKey{ed25519.PublicKey(decoded)}, nil
}

func (s KTSha256Ed25519) ParseVRFPrivateKey(raw []byte) (vrf.PrivateKey, error) {
	panic("unimplemented")
}

func (s KTSha256Ed25519) ParseVRFPublicKey(raw []byte) (vrf.PublicKey, error) {
	panic("unimplemented")
}

// ed25519PrivateKey implements the SigningPrivateKey interface for an ed25519
// private key.
type ed25519PrivateKey struct {
	inner ed25519.PrivateKey
}

func (k ed25519PrivateKey) Public() ([]byte, error) {
	return k.inner.Public().(ed25519.PublicKey), nil
}

func (k ed25519PrivateKey) Sign(message []byte) ([]byte, error) {
	return k.inner.Sign(nil, message, crypto.Hash(0))
}

// ed25519PublicKey implements the SigningPublicKey interface for an ed25519
// public key.
type ed25519PublicKey struct {
	inner ed25519.PublicKey
}

func (k ed25519PublicKey) Verify(message, sig []byte) bool {
	return ed25519.Verify(k.inner, message, sig)
}

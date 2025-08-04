package suites

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"hash"
	"math/big"

	"github.com/Bren2010/katie/crypto/vrf"
)

// KTSha256P256 implements the KT cipher suite using SHA-256 for hashing and
// P-256 for signatures and the VRF.
type KTSha256P256 struct{}

var _ CipherSuite = KTSha256P256{}

func (s KTSha256P256) Id() uint16       { return 0x01 }
func (s KTSha256P256) Hash() hash.Hash  { return sha256.New() }
func (s KTSha256P256) OpeningSize() int { return 16 }

func (s KTSha256P256) CommitmentBytes() []byte {
	return []byte{
		0xd8, 0x21, 0xf8, 0x79, 0x0d, 0x97, 0x70, 0x97,
		0x96, 0xb4, 0xd7, 0x90, 0x33, 0x57, 0xc3, 0xf5,
	}
}

func (s KTSha256P256) ParseSigningPrivateKey(raw []byte) (SigningPrivateKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("failed to decode pem block")
	}
	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ecdsaPriv, ok := priv.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("decoded private key is unexpected type")
	}
	return p256PrivateKey{ecdsaPriv}, nil
}

func (s KTSha256P256) ParseSigningPublicKey(raw []byte) (SigningPublicKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("failed to decode pem block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ecdsaPub, ok := pub.(ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("decoded public key is unexpected type")
	}
	return p256PublicKey{&ecdsaPub}, nil
}

func (s KTSha256P256) ParseVRFPrivateKey(raw []byte) (vrf.PrivateKey, error) {
	panic("unimplemented")
}

func (s KTSha256P256) ParseVRFPublicKey(raw []byte) (vrf.PublicKey, error) {
	panic("unimplemented")
}

// p256PrivateKey implements the SigningPrivateKey interface for a P-256 ECDSA
// private key.
type p256PrivateKey struct {
	inner *ecdsa.PrivateKey
}

func (k p256PrivateKey) Public() ([]byte, error) {
	return x509.MarshalPKIXPublicKey(k.inner.PublicKey)
}

func (k p256PrivateKey) Sign(message []byte) ([]byte, error) {
	digest := sha256.Sum256(message)

	r, s, err := ecdsa.Sign(rand.Reader, k.inner, digest[:])
	if err != nil {
		return nil, err
	}
	rBytes, sBytes := r.Bytes(), s.Bytes()

	sig := make([]byte, 64)
	copy(sig[32-len(rBytes):], rBytes)
	copy(sig[64-len(sBytes):], sBytes)

	return sig, nil
}

// p256PublicKey implements the SigningPublicKey interface for a P-256 ECDSA
// public key.
type p256PublicKey struct {
	inner *ecdsa.PublicKey
}

func (k p256PublicKey) Verify(message, sig []byte) bool {
	digest := sha256.Sum256(message)

	if len(sig) != 64 {
		return false
	}
	r, s := new(big.Int), new(big.Int)
	r.SetBytes(sig[:32])
	s.SetBytes(sig[32:])

	return ecdsa.Verify(k.inner, digest[:], r, s)
}

package suites

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"hash"
	"math/big"

	"github.com/Bren2010/katie/crypto/vrf"
	"github.com/Bren2010/katie/crypto/vrf/p256"
)

// KTSha256P256 implements the KT cipher suite using SHA-256 for hashing and
// P-256 for signatures and the VRF.
type KTSha256P256 struct{}

var _ CipherSuite = KTSha256P256{}

func (s KTSha256P256) Id() uint16                 { return 0x01 }
func (s KTSha256P256) Hash() hash.Hash            { return sha256.New() }
func (s KTSha256P256) HashSize() int              { return 32 }
func (s KTSha256P256) CommitmentOpeningSize() int { return 16 }
func (s KTSha256P256) VrfProofSize() int          { return 81 }

func (s KTSha256P256) CommitmentFixedBytes() []byte {
	return []byte{
		0xd8, 0x21, 0xf8, 0x79, 0x0d, 0x97, 0x70, 0x97,
		0x96, 0xb4, 0xd7, 0x90, 0x33, 0x57, 0xc3, 0xf5,
	}
}

func (s KTSha256P256) ParseSigningPrivateKey(raw []byte) (SigningPrivateKey, error) {
	priv, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), raw)
	if err != nil {
		return nil, err
	}
	return p256PrivateKey{priv}, nil
}

func (s KTSha256P256) ParseSigningPublicKey(raw []byte) (SigningPublicKey, error) {
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), raw)
	if err != nil {
		return nil, err
	}
	return p256PublicKey{pub}, nil
}

func (s KTSha256P256) ParseVRFPrivateKey(raw []byte) (vrf.PrivateKey, error) {
	return p256.NewPrivateKey(raw)
}

func (s KTSha256P256) ParseVRFPublicKey(raw []byte) (vrf.PublicKey, error) {
	return p256.NewPublicKey(raw)
}

// p256PrivateKey implements the SigningPrivateKey interface for a P-256 ECDSA
// private key.
type p256PrivateKey struct {
	inner *ecdsa.PrivateKey
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

func (k p256PrivateKey) Public() SigningPublicKey {
	return p256PublicKey{inner: &k.inner.PublicKey}
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

func (k p256PublicKey) Bytes() []byte {
	out, err := k.inner.Bytes()
	if err != nil {
		panic(err)
	}
	return out
}

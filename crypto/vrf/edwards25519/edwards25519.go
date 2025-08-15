// Package edwards25519 implements the ECVRF-EDWARDS25519-SHA512-TAI cipher
// suite from RFC 9381, with the VRF output truncated from 64 to 32 bytes.
package edwards25519

import (
	"bytes"
	"crypto/rand"
	"crypto/sha512"
	"errors"

	"filippo.io/edwards25519"
	"github.com/Bren2010/katie/crypto/vrf"
)

// encodeToCurve implements the trial-and-increment algorithm for encoding a
// byte string to a curve point.
func encodeToCurve(salt, m []byte) *edwards25519.Point {
	counter := 0

	for {
		buf := &bytes.Buffer{}
		buf.WriteByte(0x03) // Suite string
		buf.WriteByte(0x01) // Front domain separator
		buf.Write(salt)
		buf.Write(m)
		buf.WriteByte(byte(counter))
		buf.WriteByte(0x00) // Back domain separator

		hashStr := sha512.Sum512(buf.Bytes())

		// Notes on point validation:
		// - Probability of producing a non-canonical encoding is negligible.
		// - SetBytes verifies that the point is on the curve.
		// - The point may be in a small subgroup but this is permissible.
		point, err := new(edwards25519.Point).SetBytes(hashStr[:32])
		if err == nil {
			point.MultByCofactor(point)
			return point
		} else if counter == 255 {
			panic("encode to curve failed unexpectedly")
		}

		counter++
	}
}

// generateNonce deterministically generates a private key from hStr.
func generateNonce(lower, hStr []byte) *edwards25519.Scalar {
	kStr := sha512.Sum512(append(lower, hStr...))

	k, err := new(edwards25519.Scalar).SetUniformBytes(kStr[:])
	if err != nil {
		panic(err)
	}

	return k
}

// generateChallenge deterministically generates the proof challenge from the
// given elliptic curve points.
func generateChallenge(p1, p2, p3, p4, p5 *edwards25519.Point) []byte {
	buf := &bytes.Buffer{}
	buf.WriteByte(0x03) // Suite string
	buf.WriteByte(0x02) // Front domain separator
	buf.Write(p1.Bytes())
	buf.Write(p2.Bytes())
	buf.Write(p3.Bytes())
	buf.Write(p4.Bytes())
	buf.Write(p5.Bytes())
	buf.WriteByte(0x00) // Back domain separator

	cStr := sha512.Sum512(buf.Bytes())
	for i := 16; i < 32; i++ {
		cStr[i] = 0
	}

	return cStr[:32]
}

// proofToHash converts the VRF proof into the VRF output.
func proofToHash(Gamma *edwards25519.Point) [32]byte {
	buf := &bytes.Buffer{}
	buf.WriteByte(0x03) // Suite string
	buf.WriteByte(0x03) // Front domain separator
	buf.Write(new(edwards25519.Point).MultByCofactor(Gamma).Bytes())
	buf.WriteByte(0x00) // Back domain separator

	h := sha512.Sum512(buf.Bytes())

	out := [32]byte{}
	copy(out[:], h[:32])
	return out
}

type PrivateKey struct {
	scalar *edwards25519.Scalar
	point  *edwards25519.Point
	upper  []byte
}

func GeneratePrivateKey() []byte {
	k := make([]byte, 32)
	rand.Read(k)
	return k
}

func NewPrivateKey(raw []byte) (*PrivateKey, error) {
	if len(raw) != 32 {
		return nil, errors.New("vrf private key is unexpected length")
	}

	h := sha512.Sum512(raw)
	scalar, err := new(edwards25519.Scalar).SetBytesWithClamping(h[:32])
	if err != nil {
		return nil, err
	}
	point := new(edwards25519.Point).ScalarBaseMult(scalar)

	return &PrivateKey{scalar: scalar, point: point, upper: h[32:]}, nil
}

func (p *PrivateKey) Prove(m []byte) (index [32]byte, proof []byte) {
	H := encodeToCurve(p.point.Bytes(), m)
	hStr := H.Bytes()

	Gamma := new(edwards25519.Point).ScalarMult(p.scalar, H)

	k := generateNonce(p.upper, hStr)
	kB := new(edwards25519.Point).ScalarBaseMult(k)
	kH := new(edwards25519.Point).ScalarMult(k, H)

	c := generateChallenge(p.point, H, Gamma, kB, kH)

	s, err := new(edwards25519.Scalar).SetCanonicalBytes(c)
	if err != nil {
		panic(err)
	}
	s.MultiplyAdd(s, p.scalar, k)

	proof = make([]byte, 32+16+32)
	copy(proof[:32], Gamma.Bytes())
	copy(proof[32:48], c[:16])
	copy(proof[48:], s.Bytes())

	index = proofToHash(Gamma)

	return
}

func (p *PrivateKey) PublicKey() vrf.PublicKey {
	return &PublicKey{point: p.point}
}

type PublicKey struct {
	point *edwards25519.Point
}

func NewPublicKey(raw []byte) (*PublicKey, error) {
	// Notes on point validation:
	// - Non-canonical encodings are accepted but have no affect on protocol.
	// - SetBytes verifies that the point is on the curve.
	// - We manually check that the point is not in a small subgroup.
	point, err := new(edwards25519.Point).SetBytes(raw)
	if err != nil {
		return nil, err
	}
	temp := new(edwards25519.Point).MultByCofactor(point)
	if edwards25519.NewIdentityPoint().Equal(temp) == 1 {
		return nil, errors.New("public key is malformed")
	}
	return &PublicKey{point: point}, nil
}

func (p *PublicKey) Verify(m, proof []byte) (index [32]byte, err error) {
	// Decode proof.
	if len(proof) != 32+16+32 {
		return [32]byte{}, errors.New("vrf proof is invalid size")
	}

	// Notes on point validation:
	// - Non-canonical encodings are accepted but have no affect on protocol.
	// - SetBytes verifies that the point is on the curve.
	// - The point may be in a small subgroup but this is permissible.
	Gamma, err := new(edwards25519.Point).SetBytes(proof[:32])
	if err != nil {
		return [32]byte{}, err
	}

	cBytes := make([]byte, 32)
	copy(cBytes[:16], proof[32:48])
	c, err := new(edwards25519.Scalar).SetCanonicalBytes(cBytes)
	if err != nil {
		return [32]byte{}, err
	}

	s, err := new(edwards25519.Scalar).SetCanonicalBytes(proof[48:])
	if err != nil {
		return [32]byte{}, err
	}

	// Verify proof.
	H := encodeToCurve(p.point.Bytes(), m)

	U := new(edwards25519.Point).ScalarBaseMult(s)
	temp := new(edwards25519.Point).ScalarMult(c, p.point)
	temp.Negate(temp)
	U.Add(U, temp)

	V := new(edwards25519.Point).ScalarMult(s, H)
	temp.ScalarMult(c, Gamma).Negate(temp)
	V.Add(V, temp)

	cPrime := generateChallenge(p.point, H, Gamma, U, V)
	if !bytes.Equal(cBytes, cPrime) {
		return [32]byte{}, errors.New("vrf proof verification failed")
	}

	return proofToHash(Gamma), nil
}

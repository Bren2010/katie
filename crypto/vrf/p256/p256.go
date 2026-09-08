// Package p256 implements the ECVRF-P256-SHA256-TAI cipher suite from RFC 9381.
package p256

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"

	"filippo.io/bigmod"
	"filippo.io/nistec"
	"github.com/Bren2010/katie/crypto/vrf"
)

// order is the order of the P-256 base point, as a modulus for constant-time
// scalar arithmetic.
var order = func() *bigmod.Modulus {
	m, err := bigmod.NewModulus([]byte{
		0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
		0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
	})
	if err != nil {
		panic(err)
	}
	return m
}()

// newScalar returns `raw` as a scalar reduced modulo the group order, or an
// error if `raw` is not in the range [1, order-1]. It runs in constant time.
func newScalar(raw []byte) (*bigmod.Nat, error) {
	scalar, err := bigmod.NewNat().SetBytes(raw, order)
	if err != nil {
		return nil, err
	} else if scalar.IsZero() == 1 {
		return nil, errors.New("scalar is zero")
	}
	return scalar, nil
}

// encodeToCurve implements the trial-and-increment algorithm for encoding a
// byte string to a curve point.
func encodeToCurve(salt, m []byte) *nistec.P256Point {
	counter := 0

	for {
		buf := &bytes.Buffer{}
		buf.WriteByte(0x01) // Suite string
		buf.WriteByte(0x01) // Front domain separator
		buf.Write(salt)
		buf.Write(m)
		buf.WriteByte(byte(counter))
		buf.WriteByte(0x00) // Back domain separator

		hash := sha256.Sum256(buf.Bytes())

		hashStr := make([]byte, 33)
		hashStr[0] = 0x02
		copy(hashStr[1:], hash[:])

		// Notes on point validation:
		// - SetBytes verifies that the scalar is less than p.
		// - SetBytes verifies that the point is on the curve.
		// - Point can not be point at infinity because hashStr starts with 2.
		point, err := new(nistec.P256Point).SetBytes(hashStr)
		if err == nil {
			return point
		} else if counter == 255 {
			panic("encode to curve failed unexpectedly")
		}

		counter++
	}
}

func mac(key, message []byte) []byte {
	hasher := hmac.New(sha256.New, key)
	hasher.Write(message)
	return hasher.Sum(nil)
}

// generateNonce deterministically generates a private key from hStr.
func generateNonce(priv, hStr []byte) []byte {
	// a. h1 = H(m)
	//
	// Steps d and f below consume bits2octets(h1), which reduces h1 modulo the
	// group order. Since the hash output and the group order have the same bit
	// length, this only changes h1 when it's greater than or equal to the order.
	h1Sum := sha256.Sum256(hStr)
	h1Nat, err := bigmod.NewNat().SetOverflowingBytes(h1Sum[:], order)
	if err != nil {
		panic(err)
	}
	h1 := h1Nat.Bytes(order)

	// b. V = 0x01 0x01 ... 0x01
	V := make([]byte, 32)
	for i := range V {
		V[i] = 0x01
	}

	// c. K = 0x00 0x00 ... 0x00
	K := make([]byte, 32)

	// d. K = HMAC_K(V || 0x00 || priv || h1)
	buf := &bytes.Buffer{}
	buf.Write(V)
	buf.WriteByte(0x00)
	buf.Write(priv)
	buf.Write(h1)

	K = mac(K, buf.Bytes())

	// e. V = HMAC_K(V)
	V = mac(K, V)

	// f. K = HMAC_K(V || 0x01 || priv || h1)
	buf.Reset()
	buf.Write(V)
	buf.WriteByte(0x01)
	buf.Write(priv)
	buf.Write(h1)

	K = mac(K, buf.Bytes())

	// g. V = HMAC_K(v)
	V = mac(K, V)

	// h. Repeat until a proper value is found:
	for range 256 {
		// V = HMAC_K(V)
		V = mac(K, V)

		// Return if acceptable.
		if _, err := newScalar(V); err == nil {
			return V
		}

		// K = HMAC_K(V || 0x00)
		K = mac(K, append(V, 0x00))
		// V = HMAC_K(V)
		V = mac(K, V)
	}

	panic("nonce generation failed unexpectedly")
}

// generateChallenge deterministically generates the proof challenge from the
// given elliptic curve points.
func generateChallenge(p1, p2, p3, p4, p5 *nistec.P256Point) []byte {
	buf := &bytes.Buffer{}
	buf.WriteByte(0x01) // Suite string
	buf.WriteByte(0x02) // Front domain separator
	buf.Write(p1.BytesCompressed())
	buf.Write(p2.BytesCompressed())
	buf.Write(p3.BytesCompressed())
	buf.Write(p4.BytesCompressed())
	buf.Write(p5.BytesCompressed())
	buf.WriteByte(0x00) // Back domain separator

	cStr := sha256.Sum256(buf.Bytes())

	return cStr[:16]
}

// proofToHash converts the VRF proof into the VRF output.
func proofToHash(gamma []byte) []byte {
	buf := &bytes.Buffer{}
	buf.WriteByte(0x01) // Suite string
	buf.WriteByte(0x03) // Front domain separator
	buf.Write(gamma)
	buf.WriteByte(0x00) // Back domain separator

	sum := sha256.Sum256(buf.Bytes())
	return sum[:]
}

type PrivateKey struct {
	scalar []byte
	point  *nistec.P256Point
}

func GeneratePrivateKey() []byte {
	for {
		k := make([]byte, 32)
		rand.Read(k)

		if _, err := newScalar(k); err == nil {
			return k
		}
	}
}

func NewPrivateKey(raw []byte) (*PrivateKey, error) {
	if len(raw) != 32 {
		return nil, errors.New("vrf private key is unexpected length")
	}
	if _, err := newScalar(raw); err != nil {
		return nil, errors.New("vrf private key is malformed")
	}

	scalar := make([]byte, len(raw))
	copy(scalar, raw)

	point, err := new(nistec.P256Point).ScalarBaseMult(scalar)
	if err != nil {
		return nil, err
	}

	return &PrivateKey{scalar: scalar, point: point}, nil
}

func (p *PrivateKey) Prove(m []byte) (output []byte, proof []byte) {
	H := encodeToCurve(p.point.BytesCompressed(), m)
	hStr := H.BytesCompressed()

	Gamma, err := new(nistec.P256Point).ScalarMult(H, p.scalar)
	if err != nil {
		panic(err)
	}

	k := generateNonce(p.scalar, hStr)
	kB, err := new(nistec.P256Point).ScalarBaseMult(k)
	if err != nil {
		panic(err)
	}
	kH, err := new(nistec.P256Point).ScalarMult(H, k)
	if err != nil {
		panic(err)
	}
	c := generateChallenge(p.point, H, Gamma, kB, kH)

	// s = (k + c*x) mod q, computed in constant time since it involves the
	// private key.
	cNat, err := bigmod.NewNat().SetBytes(c, order)
	if err != nil {
		panic(err)
	}
	xNat, err := newScalar(p.scalar)
	if err != nil {
		panic(err)
	}
	kNat, err := newScalar(k)
	if err != nil {
		panic(err)
	}
	s := cNat.Mul(xNat, order).Add(kNat, order)

	proof = make([]byte, 33+16+32)
	copy(proof[:33], Gamma.BytesCompressed())
	copy(proof[33:49], c)
	copy(proof[49:], s.Bytes(order))

	output = proofToHash(proof[:33])

	return
}

func (p *PrivateKey) PublicKey() vrf.PublicKey {
	return &PublicKey{point: p.point}
}

type PublicKey struct {
	point *nistec.P256Point
}

func NewPublicKey(raw []byte) (*PublicKey, error) {
	// Notes on point validation:
	// - SetBytes verifies the scalar(s) are less than p.
	// - SetBytes verifies that the point is on the curve.
	// - We manually check that the point is not the point at infinity.
	if len(raw) == 1 {
		return nil, errors.New("public key is malformed")
	}
	point, err := new(nistec.P256Point).SetBytes(raw)
	if err != nil {
		return nil, err
	}
	return &PublicKey{point: point}, nil
}

func (p *PublicKey) verify(m, proof []byte) error {
	// Decode proof.
	if len(proof) != 33+16+32 {
		return errors.New("vrf proof is invalid size")
	}

	// Notes on point validation:
	// - SetBytes verifies that the scalar is less than p.
	// - SetBytes verifies that the point is on the curve.
	// - SetBytes will return an error if the first byte isn't 2 or 3 due to the
	//   input length. As such, the point can not be the point at infinity.
	Gamma, err := new(nistec.P256Point).SetBytes(proof[:33])
	if err != nil {
		return err
	}

	c := make([]byte, 32)
	copy(c[16:], proof[33:49])

	s := proof[49:]
	if _, err := bigmod.NewNat().SetBytes(s, order); err != nil {
		return errors.New("vrf proof is malformed")
	}

	// Verify proof.
	H := encodeToCurve(p.point.BytesCompressed(), m)

	U, err := new(nistec.P256Point).ScalarBaseMult(s)
	if err != nil {
		return err
	}
	temp, err := new(nistec.P256Point).ScalarMult(p.point, c)
	if err != nil {
		return err
	}
	temp.Negate(temp)
	U.Add(U, temp)

	V, err := new(nistec.P256Point).ScalarMult(H, s)
	if err != nil {
		return err
	}
	_, err = temp.ScalarMult(Gamma, c)
	if err != nil {
		return err
	}
	temp.Negate(temp)
	V.Add(V, temp)

	cPrime := generateChallenge(p.point, H, Gamma, U, V)
	if !bytes.Equal(c[16:], cPrime) {
		return errors.New("vrf proof verification failed")
	}

	return nil
}

func (p *PublicKey) Verify(m, proof []byte) (output []byte, err error) {
	err = p.verify(m, proof)
	if err != nil {
		return
	}
	output = proofToHash(proof[:33])
	return
}

func (p *PublicKey) Bytes() []byte { return p.point.BytesCompressed() }

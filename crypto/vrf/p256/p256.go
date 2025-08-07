package p256

import (
	"bytes"
	"crypto/ecdh"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha256"
	"math/big"

	"github.com/Bren2010/katie/crypto/vrf"
)

var curve = ecdh.P256()

// marshalEcdh takes the (x, y) coordinates of a curve point and returns a
// corresponding *ecdh.PublicKey structure.
func marshalEcdh(x, y *big.Int) *ecdh.PublicKey {
	buf := make([]byte, 65)
	buf[0] = 0x04
	x.FillBytes(buf[1:33])
	y.FillBytes(buf[33:])

	pub, err := curve.NewPublicKey(buf)
	if err != nil {
		panic(err)
	}
	return pub
}

// encodeToCurve implements the trial-and-increment algorithm.
func encodeToCurve(salt, m []byte) *ecdh.PublicKey {
	ellipticCurve := elliptic.P256()
	hasher := sha256.New()
	counter := 0

	for {
		buf := &bytes.Buffer{}
		buf.WriteByte(0x01) // Suite string
		buf.WriteByte(0x01) // Front domain separator
		buf.Write(salt)
		buf.Write(m)
		buf.WriteByte(byte(counter))
		buf.WriteByte(0x00) // Back domain separator

		hasher.Write(buf.Bytes())
		hashStr := hasher.Sum([]byte{0x02})

		x, y := elliptic.UnmarshalCompressed(ellipticCurve, hashStr)
		if x != nil {
			return marshalEcdh(x, y)
		} else if counter == 255 {
			panic("encode to curve failed unexpectedly")
		}

		hasher.Reset()
		counter++
	}
}

// pointToString converts an *ecdh.PublicKey to compressed NIST format.
func pointToString(pt *ecdh.PublicKey) []byte {
	encoded := pt.Bytes()

	buf := make([]byte, 33)
	buf[0] = 2 | (encoded[64] & 1)
	copy(buf[1:33], encoded[1:33])

	return buf
}

func mac(key, message []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	return mac.Sum(nil)
}

// generateNonce deterministically generates a private key from hStr.
func generateNonce(priv *ecdh.PrivateKey, hStr []byte) *ecdh.PrivateKey {
	// a. h1 = H(m)
	h1 := sha256.Sum256(hStr)

	// b. V = 0x01 0x01 ... 0x01
	V := make([]byte, 32)
	for i, _ := range V {
		V[i] = 0x01
	}

	// c. K = 0x00 0x00 ... 0x00
	K := make([]byte, 32)

	// d. K = HMAC_K(V || 0x00 || priv || h1)
	buf := &bytes.Buffer{}
	buf.Write(V)
	buf.WriteByte(0x00)
	buf.Write(priv.Bytes())
	buf.Write(h1[:])

	K = mac(K, buf.Bytes())

	// e. V = HMAC_K(V)
	V = mac(K, V)

	// f. K = HMAC_K(V || 0x01 || priv || h1)
	buf.Reset()
	buf.Write(V)
	buf.WriteByte(0x01)
	buf.Write(priv.Bytes())
	buf.Write(h1[:])

	K = mac(K, buf.Bytes())

	// g. V = HMAC_K(v)
	V = mac(K, V)

	// h. Repeat until a proper value is found:
	for i := 0; i < 256; i++ {
		// V = HMAC_K(V)
		V = mac(K, V)

		// Return if acceptable.
		out, err := curve.NewPrivateKey(V)
		if err == nil {
			return out
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
func generateChallenge(p1, p2, p4 *ecdh.PublicKey, p3, p5 []byte) *big.Int {
	buf := &bytes.Buffer{}
	buf.WriteByte(0x01) // Suite string
	buf.WriteByte(0x02) // Front domain separator
	buf.Write(pointToString(p1))
	buf.Write(pointToString(p2))
	buf.Write(pointToString(p3))
	buf.Write(pointToString(p4))
	buf.Write(pointToString(p5))
}

type PrivateKey struct {
	inner *ecdh.PrivateKey
}

var _ vrf.PrivateKey = &PrivateKey{}

func (p *PrivateKey) Prove(m []byte) (index [32]byte, proof []byte) {
	// ECVRF_prove
	Y := p.inner.PublicKey()
	H := encodeToCurve(Y.Bytes(), m)
	hStr := pointToString(H)

	Gamma, err := p.inner.ECDH(H)
	if err != nil {
		panic(err)
	}

	k := generateNonce(p.inner, hStr)
	c := generateChallenge(Y, H, Gamma, k.PublicKey(), k.ECDH(H))

	cInt := new(big.Int).SetBytes(c)
	xInt := new(big.Int).SetBytes(p.inner.Bytes())
	kInt := new(big.Int).SetBytes(k.Bytes())

	sInt := new(big.Int).Mul(cInt, xInt)
	sInt.Add(sInt, kInt).Mod(sInt, elliptic.P256().Params().N)
}

func (p *PrivateKey) Public() vrf.PublicKey {

}

package suites

import (
	"encoding/hex"
	"fmt"
	"testing"
)

type TestVector struct {
	Name  string
	Suite CipherSuite

	// A valid signing keypair.
	SigningPriv string
	SigningPub  string

	// A valid VRF keypair.
	VrfPriv string
	VrfPub  string

	Message   string
	Signature string // Signature from SigningPub over Message.

	// Keys that must be rejected by the corresponding Parse method.
	InvalidSigningPriv []string
	InvalidSigningPub  []string
	InvalidVrfPriv     []string
	InvalidVrfPub      []string
}

func hexDecode(m string) []byte {
	out, err := hex.DecodeString(m)
	if err != nil {
		panic(err)
	}
	return out
}

var vectors = []TestVector{
	{
		Name:  "KT_128_SHA256_P256",
		Suite: KTSha256P256{},

		SigningPriv: "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
		SigningPub:  "0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",

		VrfPriv: "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
		VrfPub:  "0360fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6",

		Message:   "48656c6c6f2c20576f726c6421",
		Signature: "5bd6afeedad9993ac1f7d5a85f2e65e92567b631e2cac6d00498cfc9fe37898138b26d01f24c8673c5c523a1162abcb40ad9cf30ce6115981b36846e29751e91",

		InvalidSigningPriv: []string{
			"", // Empty.
			"c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f67",     // Too short.
			"c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f672100", // Too long.
			"0000000000000000000000000000000000000000000000000000000000000000",   // Zero scalar.
			"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",   // Equal to the group order.
			"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",   // Greater than the group order.
		},
		InvalidSigningPub: []string{
			"",   // Empty.
			"00", // Point at infinity.
			"60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",     // Missing the prefix byte.
			"0360fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6",                                                                   // Compressed instead of uncompressed.
			"0560fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",   // Invalid prefix byte.
			"0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462298",   // Point not on the curve.
			"0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d446229900", // Trailing byte.
		},
		InvalidVrfPriv: []string{
			"", // Empty.
			"c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f67",     // Too short.
			"c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f672100", // Too long.
			"0000000000000000000000000000000000000000000000000000000000000000",   // Zero scalar.
			"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",   // Equal to the group order.
			"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",   // Greater than the group order.
		},
		InvalidVrfPub: []string{
			"",   // Empty.
			"00", // Point at infinity.
			"60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",   // Missing the prefix byte.
			"0560fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299", // Invalid prefix byte.
			"0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462298", // Point not on the curve.
			"03ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",                                                                 // X coordinate is greater than the field modulus.
			"0360fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb600",                                                               // Trailing byte.
		},
	},
	{
		Name:  "KT_128_SHA256_ED25519",
		Suite: KTSha256Ed25519{},

		SigningPriv: "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
		SigningPub:  "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",

		VrfPriv: "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
		VrfPub:  "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",

		Message:   "72",
		Signature: "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",

		InvalidSigningPriv: []string{
			"", // Empty.
			"4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6",     // Too short.
			"4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb00", // Too long.
		},
		InvalidSigningPub: []string{
			"",   // Empty.
			"00", // Too short.
			"3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af466",     // Too short.
			"3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c00", // Too long.
		},
		InvalidVrfPriv: []string{
			"", // Empty.
			"4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6",     // Too short.
			"4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb00", // Too long.
		},
		InvalidVrfPub: []string{
			"",   // Empty.
			"00", // Too short.
			"3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af466",     // Too short.
			"3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c00", // Too long.
			// Points in a small subgroup.
			"0100000000000000000000000000000000000000000000000000000000000000",
			"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
			"0000000000000000000000000000000000000000000000000000000000000000",
			"0000000000000000000000000000000000000000000000000000000000000080",
			"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
			"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
			"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
		},
	},
}

func TestVectors(t *testing.T) {
	for _, vector := range vectors {
		t.Run(vector.Name, func(t *testing.T) {
			cs := vector.Suite

			// Test parsing of valid signature and VRF public / private keys.
			priv, err := cs.ParseSigningPrivateKey(hexDecode(vector.SigningPriv))
			if err != nil {
				t.Fatal(err)
			} else if fmt.Sprintf("%x", priv.Public().Bytes()) != vector.SigningPub {
				t.Fatal("unexpected signing public key computed")
			}
			pub, err := cs.ParseSigningPublicKey(hexDecode(vector.SigningPub))
			if err != nil {
				t.Fatal(err)
			} else if fmt.Sprintf("%x", pub.Bytes()) != vector.SigningPub {
				t.Fatal("unexpected signing public key computed")
			}

			vrfPriv, err := cs.ParseVRFPrivateKey(hexDecode(vector.VrfPriv))
			if err != nil {
				t.Fatal(err)
			} else if fmt.Sprintf("%x", vrfPriv.PublicKey().Bytes()) != vector.VrfPub {
				t.Fatal("unexpected vrf public key computed")
			}
			vrfPub, err := cs.ParseVRFPublicKey(hexDecode(vector.VrfPub))
			if err != nil {
				t.Fatal(err)
			} else if fmt.Sprintf("%x", vrfPub.Bytes()) != vector.VrfPub {
				t.Fatal("unexpected vrf public key computed")
			}

			// The proof produced by the parsed key must be the size the cipher
			// suite advertises.
			_, proof := vrfPriv.Prove(hexDecode(vector.Message))
			if len(proof) != cs.VrfProofSize() {
				t.Fatal("vrf proof is not the advertised size")
			}

			// The signature from the test vector verifies.
			message := hexDecode(vector.Message)

			if !pub.Verify(message, hexDecode(vector.Signature)) {
				t.Fatal("unexpected verification failure")
			}
			sig, err := priv.Sign(message)
			if err != nil {
				t.Fatal(err)
			} else if !pub.Verify(message, sig) {
				t.Fatal("unexpected verification failure")
			}

			// Signature verification fails when the message or signature are
			// modified.
			if pub.Verify(append(message, 0), sig) {
				t.Fatal("unexpected verification success")
			}

			malformed := [][]byte{nil, sig[:len(sig)-1], append(sig, 0)}

			modified := make([]byte, len(sig))
			copy(modified, sig)
			modified[0] ^= 1
			malformed = append(malformed, modified)

			for _, cand := range malformed {
				if pub.Verify(message, cand) {
					t.Fatal("unexpected verification success")
				}
			}

			// Invalid public and private keys are rejected.
			cases := []struct {
				name  string
				parse func(raw []byte) error
				keys  []string
			}{
				{
					"ParseSigningPrivateKey",
					func(raw []byte) error { _, err := cs.ParseSigningPrivateKey(raw); return err },
					vector.InvalidSigningPriv,
				},
				{
					"ParseSigningPublicKey",
					func(raw []byte) error { _, err := cs.ParseSigningPublicKey(raw); return err },
					vector.InvalidSigningPub,
				},
				{
					"ParseVRFPrivateKey",
					func(raw []byte) error { _, err := cs.ParseVRFPrivateKey(raw); return err },
					vector.InvalidVrfPriv,
				},
				{
					"ParseVRFPublicKey",
					func(raw []byte) error { _, err := cs.ParseVRFPublicKey(raw); return err },
					vector.InvalidVrfPub,
				},
			}
			for _, c := range cases {
				for _, key := range c.keys {
					if err := c.parse(hexDecode(key)); err == nil {
						t.Fatalf("%v: expected key to be rejected: %v", c.name, key)
					}
				}
			}
		})
	}
}

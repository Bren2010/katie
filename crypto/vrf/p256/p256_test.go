package p256

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"
)

func TestCorrectness(t *testing.T) {
	raw := GeneratePrivateKey()
	priv, err := NewPrivateKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.PublicKey()

	output1, proof := priv.Prove([]byte("Hello, World!"))
	t.Logf("%x", output1)
	t.Logf("%x", proof)

	output2, err := pub.Verify([]byte("Hello, World!"), proof)
	if err != nil {
		t.Fatal(err)
	} else if !bytes.Equal(output1, output2) {
		t.Fatal("computed outputs do not match")
	}

	_, err = pub.Verify([]byte("Something else"), proof)
	if err == nil {
		t.Fatal("expected verification to fail")
	}
}

type TestVector struct {
	Priv    string
	Pub     string
	Message string
	Index   string
	Proof   string
}

func hexDecode(m string) []byte {
	out, err := hex.DecodeString(m)
	if err != nil {
		panic(err)
	}
	return out
}

func TestVectors(t *testing.T) {
	vectors := []TestVector{
		{
			Priv:    "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
			Pub:     "0360fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6",
			Message: "73616d706c65",
			Index:   "a3ad7b0ef73d8fc6655053ea22f9bede8c743f08bbed3d38821f0e16474b505e",
			Proof:   "035b5c726e8c0e2c488a107c600578ee75cb702343c153cb1eb8dec77f4b5071b4a53f0a46f018bc2c56e58d383f2305e0975972c26feea0eb122fe7893c15af376b33edf7de17c6ea056d4d82de6bc02f",
		},
		{
			Priv:    "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
			Pub:     "0360fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6",
			Message: "74657374",
			Index:   "a284f94ceec2ff4b3794629da7cbafa49121972671b466cab4ce170aa365f26d",
			Proof:   "034dac60aba508ba0c01aa9be80377ebd7562c4a52d74722e0abae7dc3080ddb56c19e067b15a8a8174905b13617804534214f935b94c2287f797e393eb0816969d864f37625b443f30f1a5a33f2b3c854",
		},
		{
			Priv:    "2ca1411a41b17b24cc8c3b089cfd033f1920202a6c0de8abb97df1498d50d2c8",
			Pub:     "03596375e6ce57e0f20294fc46bdfcfd19a39f8161b58695b3ec5b3d16427c274d",
			Message: "4578616d706c65207573696e67204543445341206b65792066726f6d20417070656e646978204c2e342e32206f6620414e53492e58392d36322d32303035",
			Index:   "90871e06da5caa39a3c61578ebb844de8635e27ac0b13e829997d0d95dd98c19",
			Proof:   "03d03398bf53aa23831d7d1b2937e005fb0062cbefa06796579f2a1fc7e7b8c667d091c00b0f5c3619d10ecea44363b5a599cadc5b2957e223fec62e81f7b4825fc799a771a3d7334b9186bdbee87316b1",
		},
	}

	for _, vector := range vectors {
		priv, err := NewPrivateKey(hexDecode(vector.Priv))
		if err != nil {
			t.Fatal(err)
		}
		pub := priv.PublicKey().(*PublicKey)
		if fmt.Sprintf("%x", pub.Bytes()) != vector.Pub {
			t.Fatal("unexpected public key computed")
		}
		output1, proof := priv.Prove(hexDecode(vector.Message))
		if fmt.Sprintf("%x", output1) != vector.Index {
			t.Fatal("unexpected output computed")
		} else if fmt.Sprintf("%x", proof) != vector.Proof {
			t.Fatal("unexpected proof computed")
		}
		output2, err := pub.Verify(hexDecode(vector.Message), proof)
		if err != nil {
			t.Fatal(err)
		} else if fmt.Sprintf("%x", output2) != vector.Index {
			t.Fatal("unexpected output computed")
		}
	}
}

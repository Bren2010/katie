package commitments

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/Bren2010/katie/crypto/suites"
)

func TestCorrectness(t *testing.T) {
	suite := suites.KTSha256P256{}

	opening := GenerateOpening(suite)
	commitment := Commit(suite, opening, []byte("Hello, World!"))
	ok := Verify(suite, opening, []byte("Hello, World!"), commitment)
	if !ok {
		t.Fatal("unexpected verification failure")
	}
	ok = Verify(suite, opening, []byte("Something else"), commitment)
	if ok {
		t.Fatal("unexpected verification success")
	}
}

type TestVector struct {
	Opening    string
	Body       string
	Commitment string
}

func hexDecode(m string) []byte {
	out, err := hex.DecodeString(m)
	if err != nil {
		panic(err)
	}
	return out
}

func TestVectors(t *testing.T) {
	suite := suites.KTSha256P256{}
	vectors := []TestVector{
		{
			Opening:    "000102030405060708090a0b0c0d0e0f",
			Body:       "",
			Commitment: "51dde6316662100215a7cc1878113d416ec25d9443310989e0672bac6e8ea9da",
		},
		{
			Opening:    "d1cba57a2a0e2e1b52f1e6a3c8b40d19",
			Body:       "48656c6c6f2c20576f726c6421",
			Commitment: "55648e3d5739b0b278214c2bc5799edbebc7af19d72c9bd469a04306fac47429",
		},
		{
			Opening:    "ffffffffffffffffffffffffffffffff",
			Body:       "6162636465666768696a6b6c6d6e6f707172737475767778797a303132333435363738396162636465666768696a6b6c6d6e6f70",
			Commitment: "b22629470472428dab51670022b244f184e1de87470966911e3d9064d81cb7b4",
		},
	}

	for i, vector := range vectors {
		opening := hexDecode(vector.Opening)
		body := hexDecode(vector.Body)

		commitment := Commit(suite, opening, body)
		if fmt.Sprintf("%x", commitment) != vector.Commitment {
			t.Fatalf("vector %v: unexpected commitment computed", i)
		}

		ok := Verify(suite, opening, body, hexDecode(vector.Commitment))
		if !ok {
			t.Fatalf("vector %v: unexpected verification failure", i)
		}
		ok = Verify(suite, opening, append(body, 0), hexDecode(vector.Commitment))
		if ok {
			t.Fatalf("vector %v: unexpected verification success", i)
		}
	}
}

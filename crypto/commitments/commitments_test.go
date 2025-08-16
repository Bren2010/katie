package commitments

import (
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

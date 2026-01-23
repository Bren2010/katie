// Package commitments implements a cryptographic commitment.
package commitments

import (
	"crypto/hmac"
	"crypto/rand"

	"github.com/Bren2010/katie/crypto/suites"
)

// GenerateOpening returns a randomly generated opening for a commitment.
func GenerateOpening(cs suites.CipherSuite) []byte {
	out := make([]byte, cs.CommitmentOpeningSize())
	rand.Read(out)
	return out
}

// Commit returns a cryptographic commitment to `body` with the given `opening`.
func Commit(cs suites.CipherSuite, opening, body []byte) []byte {
	mac := hmac.New(cs.Hash, cs.CommitmentFixedBytes())
	mac.Write(opening)
	mac.Write(body)
	return mac.Sum(nil)
}

// Verify returns an error if `commitment` does not correspond to a commitment
// to `body` with the given `opening.`
func Verify(cs suites.CipherSuite, opening, body, commitment []byte) bool {
	cand := Commit(cs, opening, body)
	return hmac.Equal(commitment, cand)
}

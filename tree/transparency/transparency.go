// Package transparency implements a
package transparency

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"time"

	"github.com/JumpPrivacy/katie/crypto/commitments"
	"github.com/JumpPrivacy/katie/crypto/vrf"
	"github.com/JumpPrivacy/katie/db"
	"github.com/JumpPrivacy/katie/tree/log"
	"github.com/JumpPrivacy/katie/tree/prefix"
)

func leafHash(raw []byte) []byte {
	input := append([]byte("Key Transparency"), raw...)
	output := sha256.Sum256(input)
	return output[:]
}

// VrfOutput wraps the VRF-related components of a SearchResult.
type VrfOutput struct {
	Index []byte `json:"index"`
	Proof []byte `json:"proof"`
}

// SearchResult is the output from executing a search in the tree, containing a
// cryptographic proof of inclusion or non-inclusion.
type SearchResult struct {
	Root *db.TransparencyTreeRoot `json:"root"`
	Vrf  *VrfOutput               `json:"vrf"`
}

type rootTbs struct {
	SignatureKey []byte `json:"signing"`
	VrfKey       []byte `json:"vrf"`
	TreeSize     uint64 `json:"n"`
	Timestamp    int64  `json:"ts"`
	Root         []byte `json:"root"`
}

// Tree is an implementation of a transparency tree that handles all state
// management, the evaluation of a VRF, and generating/opening commitments.
type Tree struct {
	sigKey *ecdsa.PrivateKey
	vrfKey vrf.PrivateKey
	tx     db.TransparencyStore

	latest *db.TransparencyTreeRoot
}

func NewTree(sigKey *ecdsa.PrivateKey, vrfKey vrf.PrivateKey, tx db.TransparencyStore) (*Tree, error) {
	latest, err := tx.GetRoot()
	if err != nil {
		return nil, err
	}
	return &Tree{
		sigKey: sigKey,
		vrfKey: vrfKey,
		tx:     tx,

		latest: latest,
	}, nil
}

// GetConsistencyProof returns a proof that the current log with n elements is
// an extension of a previous log root with m elements, 0 < m < n.
func (t *Tree) GetConsistency(m, n int) ([][]byte, error) {
	if n > int(t.latest.TreeSize) {
		return nil, errors.New("newer value is greater than log size")
	}
	return log.NewTree(t.tx.LogStore()).GetConsistencyProof(m, n)
}

func (t *Tree) Search(key string) (*SearchResult, error) {
	index, vrfProof := t.vrfKey.Evaluate([]byte(key))

	return &SearchResult{
		Root: t.latest,
		Vrf: &VrfOutput{
			Index: index[:],
			Proof: vrfProof,
		},
	}, nil
}

// Insert adds a new key/value pair to the tree and returns an immediate proof
// of inclusion for it.
func (t *Tree) Insert(key string, value []byte) (*SearchResult, error) {
	// Produce a commitment to the user's data.
	nonce, err := commitments.GenCommitmentKey()
	if err != nil {
		return nil, err
	}
	commitment := commitments.Commit(key, value, nonce)

	// Insert the user's VRF-masked key in the prefix tree.
	index, _ := t.vrfKey.Evaluate([]byte(key))

	proot, _, err := prefix.NewTree(t.tx.PrefixStore()).Insert(t.latest.TreeSize, index[:])
	if err != nil {
		return nil, err
	}

	// Produce the leaf value that will be added to the log.
	leaf := new(bytes.Buffer)
	leaf.Write(proot)
	leaf.Write(commitment)
	leaf.Write(nonce)
	buf := leaf.Bytes()

	h := leafHash(buf[:len(proot)+len(commitment)])

	// Store the leaf and insert its hash into the log.
	if err := t.tx.Set(t.latest.TreeSize, buf); err != nil {
		return nil, err
	}
	root, err := log.NewTree(t.tx.LogStore()).Append(int(t.latest.TreeSize), h)
	if err != nil {
		return nil, err
	}

	// Produce a new signed tree root.
	sigPub := t.sigKey.Public().(*ecdsa.PublicKey)
	vrfPub := t.vrfKey.Public().(*ecdsa.PublicKey)
	treeSize := t.latest.TreeSize + 1
	ts := time.Now().UnixMilli()

	tbs, err := json.Marshal(rootTbs{
		SignatureKey: elliptic.Marshal(sigPub.Curve, sigPub.X, sigPub.Y),
		VrfKey:       elliptic.Marshal(vrfPub.Curve, vrfPub.X, vrfPub.Y),
		TreeSize:     treeSize,
		Timestamp:    ts,
		Root:         root,
	})
	if err != nil {
		return nil, err
	}
	tbsHash := sha256.Sum256(tbs)

	sig, err := t.sigKey.Sign(rand.Reader, tbsHash[:], crypto.SHA256)
	if err != nil {
		return nil, err
	}
	str := &db.TransparencyTreeRoot{TreeSize: treeSize, Timestamp: ts, Signature: sig}

	// Store the new tree root and commit all pending changes.
	if err := t.tx.SetRoot(str); err != nil {
		return nil, err
	} else if err := t.tx.Commit(); err != nil {
		return nil, err
	}
	t.latest = str

	return t.Search(key)
}

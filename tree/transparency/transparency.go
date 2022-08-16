// Package transparency implements a transparency tree that supports blinded
// searches and efficient auditing.
package transparency

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
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

// SearchStep is the output of one step of a binary search through the log.
type SearchStep struct {
	Prefix     *prefix.SearchResult `json:"prefix"`
	Commitment []byte               `json:"commitment"`
}

// SearchValue is the account data returned by a search, if any.
type SearchValue struct {
	Opening []byte `json:"opening"`
	Value   []byte `json:"value"`
}

// SearchResult is the output from executing a search in the tree, creating a
// cryptographic proof of inclusion or non-inclusion.
type SearchResult struct {
	Root        *db.TransparencyTreeRoot `json:"root"`
	Consistency [][]byte                 `json:"consistency,omitempty"`
	Vrf         *VrfOutput               `json:"vrf"`
	Search      []SearchStep             `json:"search"`
	Log         [][]byte                 `json:"log"`
	Value       *SearchValue             `json:"value,omitempty"`
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
	sigKey ed25519.PrivateKey
	vrfKey vrf.PrivateKey
	tx     db.TransparencyStore

	latest *db.TransparencyTreeRoot
}

func NewTree(sigKey ed25519.PrivateKey, vrfKey vrf.PrivateKey, tx db.TransparencyStore) (*Tree, error) {
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

func (t *Tree) SetLatest(latest *db.TransparencyTreeRoot) {
	t.latest = latest
}

// GetConsistencyProof returns a proof that the current log with n elements is
// an extension of a previous log root with m elements, 0 < m < n.
func (t *Tree) GetConsistency(m, n int) ([][]byte, error) {
	if n > int(t.latest.TreeSize) {
		return nil, errors.New("newer value is greater than log size")
	}
	return log.NewTree(t.tx.LogStore()).GetConsistencyProof(m, n)
}

// Search searches for `key` in the tree and returns a proof of inclusion or
// non-inclusion.
func (t *Tree) Search(key string) (*SearchResult, error) {
	var ids []int
	var searchOutput []SearchStep
	var journals [][]byte

	logTree := log.NewTree(t.tx.LogStore())
	prefixTree := prefix.NewTree(t.tx.PrefixStore())
	index, vrfProof := t.vrfKey.Evaluate([]byte(key))

	guide := newProofGuide(t.latest.TreeSize)
	for {
		done, err := guide.done()
		if err != nil {
			return nil, err
		} else if done {
			break
		}
		id := guide.next()

		prefixProof, err := prefixTree.Search(id+1, index[:])
		if err != nil {
			return nil, err
		}
		journal, err := t.tx.Get(id)
		if err != nil {
			return nil, err
		}

		guide.insert(id, prefixProof.Counter())

		ids = append(ids, int(id))
		searchOutput = append(searchOutput, SearchStep{
			Prefix:     prefixProof,
			Commitment: journal[0:32],
		})
		journals = append(journals, journal)
	}

	logProof, err := logTree.GetBatch(ids, int(t.latest.TreeSize))
	if err != nil {
		return nil, err
	}

	var value *SearchValue
	if i := guide.final(); i != -1 {
		value = &SearchValue{
			Opening: journals[i][32:48],
			Value:   journals[i][48:],
		}
	}

	return &SearchResult{
		Root: t.latest,
		Vrf: &VrfOutput{
			Index: index[:],
			Proof: vrfProof,
		},
		Search: searchOutput,
		Log:    logProof,
		Value:  value,
	}, nil
}

// Insert adds a new key/value pair to the tree and returns an immediate proof
// of inclusion for it.
func (t *Tree) Insert(key string, value []byte) (*db.TransparencyTreeRoot, error) {
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

	// Store the nonce and account data.
	journal := new(bytes.Buffer)
	journal.Write(commitment)
	journal.Write(nonce)
	journal.Write(value)
	if err := t.tx.Put(t.latest.TreeSize, journal.Bytes()); err != nil {
		return nil, err
	}

	// Add a new leaf to the log tree.
	leaf := new(bytes.Buffer)
	leaf.Write(proot)
	leaf.Write(commitment)
	h := leafHash(leaf.Bytes())

	root, err := log.NewTree(t.tx.LogStore()).Append(int(t.latest.TreeSize), h)
	if err != nil {
		return nil, err
	}

	// Produce a new signed tree root.
	vrfPub := t.vrfKey.Public().(*ecdsa.PublicKey)
	treeSize := t.latest.TreeSize + 1
	ts := time.Now().UnixMilli()

	tbs, err := json.Marshal(rootTbs{
		SignatureKey: t.sigKey.Public().(ed25519.PublicKey),
		VrfKey:       elliptic.Marshal(vrfPub.Curve, vrfPub.X, vrfPub.Y),
		TreeSize:     treeSize,
		Timestamp:    ts,
		Root:         root,
	})
	if err != nil {
		return nil, err
	}

	sig, err := t.sigKey.Sign(rand.Reader, tbs, crypto.Hash(0))
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

	return t.latest, nil
}

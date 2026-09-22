// Package auditor implements a stateful Third-Party Auditor for a Transparency
// Log.
package auditor

import (
	"bytes"
	"errors"
	"math/bits"

	"github.com/Bren2010/katie/crypto/suites"
	"github.com/Bren2010/katie/db"
	"github.com/Bren2010/katie/tree/log"
	"github.com/Bren2010/katie/tree/prefix"
	"github.com/Bren2010/katie/tree/transparency/algorithms"
	"github.com/Bren2010/katie/tree/transparency/math"
	"github.com/Bren2010/katie/tree/transparency/structs"
)

// Auditor represents a Third-Party Auditor of a Transparency Log.
type Auditor struct {
	config       *structs.PublicConfig
	auditorKey   suites.SigningPrivateKey
	tx           db.AuditorStore
	allowPruning bool

	state *auditorState
}

// NewAuditor returns a new Third-Party Auditor for a Transparency Log.
//
// `config` is the Transparency Log's public configuration, `auditorKey` is the
// auditor's private signing key, and `tx` is the auditor's persistent storage.
//
// `allowPruning` is set to true if the auditor should allow the Transparency
// Log to prune Prefix Tree entries. If true, the auditor retains all VRF
// outputs added since the last distinguished log entry. If false, the auditor's
// state is much smaller but any deletions from the Prefix Tree are rejected.
// This value must always be the same for the lifetime of the auditor.
func NewAuditor(
	config *structs.PublicConfig,
	auditorKey suites.SigningPrivateKey,
	tx db.AuditorStore,
	allowPruning bool,
) (*Auditor, error) {
	if config.Mode != structs.ThirdPartyAuditing {
		return nil, errors.New("transparency log is not configured with third party auditor")
	} else if !bytes.Equal(config.AuditorPublicKey.Bytes(), auditorKey.Public().Bytes()) {
		return nil, errors.New("auditor private key does not match transparency log configuration")
	}

	raw, err := tx.GetState()
	if err != nil {
		return nil, err
	}
	var state *auditorState
	if raw != nil {
		buf := bytes.NewBuffer(raw)
		state, err = newAuditorState(config.Suite, buf)
		if err != nil {
			return nil, err
		} else if buf.Len() != 0 {
			return nil, errors.New("unexpected data appended to auditor state")
		} else if state.treeHead.TreeSize <= config.AuditorStartPos {
			return nil, errors.New("configuration has unexpected tree size")
		}
	}

	return &Auditor{
		config:       config,
		auditorKey:   auditorKey,
		tx:           tx,
		allowPruning: allowPruning,

		state: state,
	}, nil
}

// Initialize provides the initial state for the auditor. This must be called if
// the auditor's starting position is greater than 0; otherwise, the auditor is
// initialized on the first call to Process with default values.
func (a *Auditor) Initialize(
	fullSubtrees [][]byte,
	timestamps []uint64,
	prefixTree []byte,
) error {
	if a.state != nil {
		return errors.New("auditor state is already initialized")
	}

	if len(fullSubtrees) != bits.OnesCount64(a.config.AuditorStartPos) {
		return errors.New("unexpected number of full subtrees provided")
	}
	for _, subtree := range fullSubtrees {
		if len(subtree) != a.config.Suite.HashSize() {
			return errors.New("unexpected subtree hash size")
		}
	}

	if len(timestamps) != len(math.Frontier(a.config.AuditorStartPos)) {
		return errors.New("unexpected number of timestamps provided")
	}
	for i := 1; i < len(timestamps); i++ {
		if timestamps[i-1] > timestamps[i] {
			return errors.New("timestamps are not monotonically increasing")
		}
	}

	if len(prefixTree) != a.config.Suite.HashSize() {
		return errors.New("unexpected prefix tree hash size")
	}

	timestamp := uint64(0)
	if len(timestamps) > 0 {
		timestamp = timestamps[len(timestamps)-1]
	}
	a.state = &auditorState{
		treeHead: structs.AuditorTreeHead{
			Timestamp: timestamp,
			TreeSize:  a.config.AuditorStartPos,
			Signature: nil,
		},
		fullSubtrees: fullSubtrees,
		timestamps:   timestamps,
		prefixTree:   prefixTree,

		inserted: nil,
	}
	return nil
}

func (a *Auditor) previousRightmost(added uint64) (*uint64, *algorithms.DataProvider, error) {
	// Build the set of relevant log entry timestamps (= the frontier timestamps
	// we've retained + the new rightmost log entry timestamp).
	n := uint64(0)
	logEntries := make(map[uint64]structs.LogEntry)

	if a.state != nil {
		n = a.state.treeHead.TreeSize
		for i, x := range math.Frontier(n) {
			logEntries[x] = structs.LogEntry{Timestamp: a.state.timestamps[i]}
		}
	}
	logEntries[n] = structs.LogEntry{Timestamp: added}

	// Pass the log entries into a DataProvider as retained state and compute
	// the previous rightmost distinguished log entry.
	provider := algorithms.NewDataProvider(a.config.Suite, nil)
	if err := provider.AddRetained(nil, logEntries); err != nil {
		return nil, nil, err
	}
	prevDLE, err := algorithms.PreviousRightmost(a.config, n+1, provider)
	if err != nil {
		return nil, nil, err
	}

	return prevDLE, provider, nil
}

func (a *Auditor) updateState(
	provider *algorithms.DataProvider,
	added []prefix.Entry,
	entry structs.LogEntry,
) error {
	var (
		n            uint64 = 0
		fullSubtrees [][]byte
		inserted     []insertedVrfOutput
	)
	if a.state != nil {
		n = a.state.treeHead.TreeSize
		fullSubtrees = a.state.fullSubtrees
		inserted = a.state.inserted
	}

	// Compute the new set of full subtrees of the log tree.
	leaf, err := entry.Hash(a.config.Suite)
	if err != nil {
		return err
	}
	fullSubtrees, err = log.Append(a.config.Suite, n, fullSubtrees, leaf)
	if err != nil {
		return err
	}

	// Compute the new set of retained timestamps.
	frontier := math.Frontier(n + 1)
	timestamps := make([]uint64, len(frontier))
	for i, x := range frontier {
		timestamp, err := provider.GetTimestamp(x)
		if err != nil {
			return err
		}
		timestamps[i] = timestamp
	}

	// Compute the new set of recently-inserted VRF outputs to retain.
	if a.allowPruning {
		rightmost, err := algorithms.RightmostDistinguished(a.config, n+1, provider)
		if err != nil {
			return err
		}
		insertedNow := make([]insertedVrfOutput, len(added))
		for i, entry := range added {
			insertedNow[i] = insertedVrfOutput{pos: n, vrfOutput: entry.VrfOutput}
		}
		inserted = mergeInserted(inserted, insertedNow, rightmost)
	} else {
		inserted = nil
	}

	a.state = &auditorState{
		treeHead: structs.AuditorTreeHead{
			Timestamp: entry.Timestamp,
			TreeSize:  n + 1,
			Signature: nil,
		},
		fullSubtrees: fullSubtrees,
		timestamps:   timestamps,
		prefixTree:   entry.PrefixTree,

		inserted: inserted,
	}
	return nil
}

// Process takes an AuditorUpdate as input and updates the auditor's internal
// state, returning an error if any issues with the update were detected. If the
// update fails to process, no auditor state is changed. Successfully processed
// updates are not persisted until `Commit` is called.
func (a *Auditor) Process(update *structs.AuditorUpdate) error {
	if a.state == nil {
		if a.config.AuditorStartPos > 0 {
			return errors.New("auditor state is not initialized")
		}
		err := a.Initialize(nil, nil, make([]byte, a.config.Suite.HashSize()))
		if err != nil {
			return err
		}
	}
	// Verify that `timestamp` is greater than or equal to the timestamp of the
	// previous log entry.
	if update.Timestamp < a.state.treeHead.Timestamp {
		return errors.New("update timestamp is less than rightmost timestamp")
	}

	// Verification steps 2 through 4 happen in EvaluateBeforeAfter.

	// For each element of `removed`, verify that the prefix leaf was published
	// in at least one distinguished log entry.
	prevDLE, provider, err := a.previousRightmost(update.Timestamp)
	if err != nil {
		return err
	}
	if len(update.Removed) > 0 {
		if !a.allowPruning || prevDLE == nil || *prevDLE < a.config.AuditorStartPos {
			return errors.New("prefix tree leaf is not eligible for removal")
		}
	}
	for _, entry := range update.Removed {
		if a.state.addedSince(*prevDLE, entry.VrfOutput) {
			return errors.New("prefix tree leaf is not eligible for removal")
		}
	}

	// Compute the root value of the previous prefix tree. Verify that it
	// matches the auditor's state. Compute the new root value for the prefix
	// tree.
	before, after, err := prefix.EvaluateBeforeAfter(a.config.Suite, update.Added, update.Removed, update.Leaves, &update.Proof)
	if err != nil {
		return err
	} else if a.state != nil && !bytes.Equal(before, a.state.prefixTree) {
		return errors.New("prefix tree root does not match expected")
	}

	// Update the auditor's state with the new log entry.
	logEntry := structs.LogEntry{Timestamp: update.Timestamp, PrefixTree: after}
	return a.updateState(provider, update.Added, logEntry)
}

// Commit signs the auditor's tree head, commits it to the database, and returns
// it.
func (a *Auditor) Commit() (*structs.AuditorTreeHead, error) {
	if a.state == nil || a.state.treeHead.TreeSize == 0 {
		return nil, errors.New("can not commit empty state")
	} else if a.state.treeHead.TreeSize == a.config.AuditorStartPos {
		return nil, errors.New("no entries processed")
	} else if a.state.treeHead.Signature != nil {
		return &a.state.treeHead, nil
	}

	// Sign the new auditor tree head.
	root, err := log.Root(a.config.Suite, a.state.treeHead.TreeSize, a.state.fullSubtrees)
	if err != nil {
		return nil, err
	}
	tbs, err := structs.Marshal(&structs.AuditorTreeHeadTBS{
		Config:    a.config,
		Timestamp: a.state.treeHead.Timestamp,
		TreeSize:  a.state.treeHead.TreeSize,
		Root:      root,
	})
	if err != nil {
		return nil, err
	}
	a.state.treeHead.Signature, err = a.auditorKey.Sign(tbs)
	if err != nil {
		return nil, err
	}

	// Serialize the auditor's state and commit it to the database.
	raw, err := a.state.Marshal()
	if err != nil {
		a.state.treeHead.Signature = nil
		return nil, err
	} else if err := a.tx.PutState(raw); err != nil {
		a.state.treeHead.Signature = nil
		return nil, err
	}

	return &a.state.treeHead, nil
}

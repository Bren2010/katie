// Package auditor implements a stateful third-party auditor for a transparency
// log.
package auditor

import (
	"bytes"
	"errors"

	"github.com/Bren2010/katie/crypto/suites"
	"github.com/Bren2010/katie/db"
	"github.com/Bren2010/katie/tree/log"
	"github.com/Bren2010/katie/tree/prefix"
	"github.com/Bren2010/katie/tree/transparency/algorithms"
	"github.com/Bren2010/katie/tree/transparency/math"
	"github.com/Bren2010/katie/tree/transparency/structs"
)

// Auditor wraps the state of a third-party auditor.
type Auditor struct {
	config     *structs.PublicConfig
	auditorKey suites.SigningPrivateKey
	tx         db.AuditorStore

	state *AuditorState
}

// NewAuditor returns a new Auditor. `config` is the transparency log's public
// configuration, `auditorKey` is the auditor's private key, and `tx` is a
// connection to the auditor's storage.
func NewAuditor(
	config *structs.PublicConfig,
	auditorKey suites.SigningPrivateKey,
	tx db.AuditorStore,
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
	var state *AuditorState
	if raw != nil {
		buf := bytes.NewBuffer(raw)
		state, err = NewAuditorState(buf)
		if err != nil {
			return nil, err
		} else if buf.Len() != 0 {
			return nil, errors.New("unexpected data appended to auditor tree head")
		}
	}

	return &Auditor{
		config:     config,
		auditorKey: auditorKey,
		tx:         tx,

		state: state,
	}, nil
}

func (a *Auditor) previousRightmost(added uint64) (*uint64, *algorithms.DataProvider, error) {
	// Build the set of relevant log entry timestamps (= the frontier timestamps
	// we've retained + the new rightmost log entry timestamp).
	n := uint64(0)
	logEntries := make(map[uint64]structs.LogEntry)

	if a.state != nil {
		n = a.state.TreeHead.TreeSize

		frontier := math.Frontier(n)
		if len(frontier) != len(a.state.Timestamps) {
			return nil, nil, errors.New("unexpected number of timestamps in auditor state")
		}
		for i, x := range frontier {
			logEntries[x] = structs.LogEntry{Timestamp: a.state.Timestamps[i]}
		}
	}

	logEntries[n] = structs.LogEntry{Timestamp: added}

	// Pass the log entries into a DataProvider as retained state and compute
	// the previous rightmost distinguished log entry.
	provider := algorithms.NewDataProvider(a.config.Suite, nil)
	provider.AddRetained(nil, logEntries)
	prevDLE, err := algorithms.PreviousRightmost(a.config, n+1, provider)
	if err != nil {
		return nil, nil, err
	}

	return prevDLE, provider, nil
}

func (a *Auditor) updateState(provider *algorithms.DataProvider, entry structs.LogEntry) error {
	n := uint64(0)
	var fullSubtrees [][]byte
	if a.state != nil {
		n = a.state.TreeHead.TreeSize
		fullSubtrees = a.state.FullSubtrees
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
	timestamps := make([]uint64, 0)
	for _, x := range math.Frontier(n + 1) {
		timestamp, err := provider.GetTimestamp(x)
		if err != nil {
			return err
		}
		timestamps = append(timestamps, timestamp)
	}

	a.state = &AuditorState{
		TreeHead: structs.AuditorTreeHead{
			Timestamp: entry.Timestamp,
			TreeSize:  n + 1,
			Signature: nil,
		},
		FullSubtrees: fullSubtrees,
		Timestamps:   timestamps,
		PrefixTree:   entry.PrefixTree,
	}
	return nil
}

// Process takes an AuditorUpdate as input and updates the auditor's internal
// state, returning an error if any issues are detected. If the update fails to
// process, no auditor state is changed. Successfully processed AuditorUpdate
// structures are not persisted to the database until `Commit` is called.
func (a *Auditor) Process(update *structs.AuditorUpdate) error {
	// Verify that `timestamp` is greater than or equal to the rightmost log
	// entry's timestamp.
	if a.state != nil && update.Timestamp < a.state.TreeHead.Timestamp {
		return errors.New("update timestamp is less than rightmost timestamp")
	}

	// Verify that the result provided in `proof` for each element of `added`
	// shows non-inclusion.
	if len(update.Proof.Results) != len(update.Added)+len(update.Removed) {
		return errors.New("unexpected number of prefix proof results")
	}
	for i, entry := range update.Added {
		res := update.Proof.Results[i]
		if !res.Inclusion() {
			continue
		}
		// Check if the same VRF output is in `removed`.
		found := false
		for _, removed := range update.Removed {
			if bytes.Equal(entry.VrfOutput, removed.VrfOutput) {
				found = true
				break
			}
		}
		if !found {
			return errors.New("proof shows inclusion for added leaf")
		}
	}

	// Verify that the result provided in `proof` for each element of `removed`
	// shows inclusion.
	for i := range update.Removed {
		res := update.Proof.Results[len(update.Added)+i]
		if !res.Inclusion() {
			return errors.New("proof shows non-inclusion for removed leaf")
		}
	}

	// For each element of `removed`, verify that the prefix leaf was published
	// in at least one distinguished log entry.
	prevDLE, provider, err := a.previousRightmost(update.Timestamp)
	if err != nil {
		return err
	} else if prevDLE == nil && len(update.Removed) > 0 {
		return errors.New("prefix tree leaf is not eligible for removal")
	}
	for _, entry := range update.Removed {
		if a.state.AddedSince(*prevDLE, entry.VrfOutput) {
			return errors.New("prefix tree leaf is not eligible for removal")
		}
	}

	// Compute the root value of the previous prefix tree. Verify that it
	// matches the auditor's state. Compute the new root value for the prefix
	// tree.
	before, after, err := prefix.EvaluateBeforeAfter(a.config.Suite, update.Added, update.Removed, &update.Proof)
	if err != nil {
		return err
	} else if a.state != nil && !bytes.Equal(before, a.state.PrefixTree) {
		return errors.New("prefix tree root does not match expected")
	}

	// Update the auditor's state with the new log entry.
	logEntry := structs.LogEntry{Timestamp: update.Timestamp, PrefixTree: after}
	return a.updateState(provider, logEntry)
}

// Commit signs the auditor's tree head, commits it to the database, and returns
// it.
func (a *Auditor) Commit() (*structs.AuditorTreeHead, error) {
	if a.state == nil {
		return nil, errors.New("can not commit empty state")
	} else if a.state.TreeHead.Signature != nil {
		return &a.state.TreeHead, nil
	}

	// Sign the new auditor tree head.
	root, err := log.Root(a.config.Suite, a.state.TreeHead.TreeSize, a.state.FullSubtrees)
	if err != nil {
		return nil, err
	}
	tbs, err := structs.Marshal(&structs.AuditorTreeHeadTBS{
		Config:    a.config,
		Timestamp: a.state.TreeHead.Timestamp,
		TreeSize:  a.state.TreeHead.TreeSize,
		Root:      root,
	})
	if err != nil {
		return nil, err
	}
	a.state.TreeHead.Signature, err = a.auditorKey.Sign(tbs)
	if err != nil {
		return nil, err
	}

	// Serialize the auditor's state and commit it to the database.
	raw, err := a.state.Marshal()
	if err != nil {
		return nil, err
	} else if err := a.tx.PutState(raw); err != nil {
		return nil, err
	}

	return &a.state.TreeHead, nil
}

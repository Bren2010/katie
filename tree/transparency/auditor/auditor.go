package auditor

import (
	"bytes"
	"errors"

	"github.com/Bren2010/katie/crypto/suites"
	"github.com/Bren2010/katie/db"
	"github.com/Bren2010/katie/tree/prefix"
	"github.com/Bren2010/katie/tree/transparency/algorithms"
	"github.com/Bren2010/katie/tree/transparency/math"
	"github.com/Bren2010/katie/tree/transparency/structs"
)

type Auditor struct {
	config     *structs.PublicConfig
	auditorKey suites.SigningPrivateKey
	tx         db.AuditorStore

	state *AuditorState
}

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

func (a *Auditor) previousRightmost(added uint64) (*uint64, error) {
	if a.state == nil {
		return nil, nil
	}
	n := a.state.TreeHead.TreeSize

	// Build the set of relevant log entry timestamps (the frontier timestamps
	// we've retained and the new rightmost log entry timestamp), and pass them
	// into a DataProvider as retained data.
	logEntries := make(map[uint64]structs.LogEntry)
	for i, x := range math.Frontier(n) {
		logEntries[x] = structs.LogEntry{Timestamp: a.state.Timestamps[i]}
	}
	logEntries[n] = structs.LogEntry{Timestamp: added}

	provider := algorithms.NewDataProvider(a.config.Suite, nil)
	provider.AddRetained(nil, logEntries)

	// Compute the previous rightmost distinguished log entry.
	return algorithms.PreviousRightmost(a.config, n+1, provider)
}

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
	prevDLE, err := a.previousRightmost(update.Timestamp)
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
	} else if a.state != nil && !bytes.Equal(before, a.state.PrefixRoot) {
		return errors.New("prefix tree root does not match expected")
	}

	// Compute the new root of the log tree.
	logEntry := structs.LogEntry{Timestamp: update.Timestamp, PrefixTree: after}

}

func (a *Auditor) TreeHead() *structs.AuditorTreeHead { return a.state.TreeHead }

package transparency

import (
	"bytes"
	"errors"
	"slices"

	"github.com/Bren2010/katie/crypto/suites"
	"github.com/Bren2010/katie/tree/log"
	"github.com/Bren2010/katie/tree/transparency/math"
	"github.com/Bren2010/katie/tree/transparency/structs"
)

type sortableLogLeaf struct {
	position uint64
	structs.LogEntry
}

func sortLogLeaf(a, b sortableLogLeaf) int {
	if a.position < b.position {
		return -1
	} else if a.position > b.position {
		return 1
	}
	return 0
}

func addTimestamp(collection map[uint64]uint64, pos1, ts1 uint64) error {
	for pos2, ts2 := range collection {
		if pos1 == pos2 {
			return errors.New("can not insert same timestamp multiple times")
		} else if pos1 < pos2 && ts1 > ts2 || pos1 > pos2 && ts1 < ts2 {
			return errors.New("timestamps are not monotonic")
		}
	}
	collection[pos1] = ts1
	return nil
}

func addPrefixTree(collection map[uint64][]byte, pos uint64, root []byte) error {
	existing, ok := collection[pos]
	if ok && !bytes.Equal(root, existing) {
		return errors.New("conflicting values for prefix tree root hash found")
	} else if !ok {
		collection[pos] = root
	}
	return nil
}

// dataProvider is given as an input to several of the algorithm
// implementations. It handles the deduplication aspect of extracting
// information from a CombinedTreeProof.
type dataProvider struct {
	cs     suites.CipherSuite
	handle proofHandle

	fullSubtrees [][]byte                    // Retained full subtrees of the log tree.
	logEntries   map[uint64]structs.LogEntry // Retained log entries.

	timestamps  map[uint64]uint64 // Map from log entry to timestamp.
	prefixTrees map[uint64][]byte // Map from log entry to prefix tree root value.
}

func newDataProvider(cs suites.CipherSuite, handle proofHandle) *dataProvider {
	return &dataProvider{
		cs:     cs,
		handle: handle,

		timestamps:  make(map[uint64]uint64),
		prefixTrees: make(map[uint64][]byte),
	}
}

func (dp *dataProvider) AddRetained(fullSubtrees [][]byte, logEntries map[uint64]structs.LogEntry) error {
	dp.fullSubtrees = fullSubtrees
	dp.logEntries = logEntries

	for pos, leaf := range logEntries {
		if err := addTimestamp(dp.timestamps, pos, leaf.Timestamp); err != nil {
			return err
		} else if err := addPrefixTree(dp.prefixTrees, pos, leaf.PrefixTree); err != nil {
			return err
		}
	}

	return nil
}

func (dp *dataProvider) GetTimestamp(x uint64) (uint64, error) {
	if ts, ok := dp.timestamps[x]; ok {
		return ts, nil
	}
	ts, err := dp.handle.GetTimestamp(x)
	if err != nil {
		return 0, err
	} else if err := addTimestamp(dp.timestamps, x, ts); err != nil {
		return 0, err
	}
	return ts, nil
}

func (dp *dataProvider) GetSearchBinaryLadder(x uint64, ver uint32, omit bool) (int, error) {
	if _, err := dp.GetTimestamp(x); err != nil {
		return 0, err
	}
	root, res, err := dp.handle.GetSearchBinaryLadder(x, ver, omit)
	if err != nil {
		return 0, err
	} else if err := addPrefixTree(dp.prefixTrees, x, root); err != nil {
		return 0, err
	}
	return res, nil
}

func (dp *dataProvider) GetMonitoringBinaryLadder(x uint64, ver uint32) error {
	if _, err := dp.GetTimestamp(x); err != nil {
		return err
	}
	root, err := dp.handle.GetMonitoringBinaryLadder(x, ver)
	if err != nil {
		return err
	}
	return addPrefixTree(dp.prefixTrees, x, root)
}

func (dp *dataProvider) GetInclusionProof(x uint64, ver uint32) error {
	if _, err := dp.GetTimestamp(x); err != nil {
		return err
	}
	root, err := dp.handle.GetInclusionProof(x, ver)
	if err != nil {
		return err
	}
	return addPrefixTree(dp.prefixTrees, x, root)
}

func (dp *dataProvider) inspectedLeaves() ([]sortableLogLeaf, error) {
	leaves := make([]sortableLogLeaf, 0)

	// Put together initial list of leaves that were inspected by our proof and
	// sort them.
	for x, ts := range dp.timestamps {
		if _, ok := dp.logEntries[x]; ok {
			continue
		}
		leaves = append(leaves, sortableLogLeaf{
			position: x,
			LogEntry: structs.LogEntry{Timestamp: ts, PrefixTree: dp.prefixTrees[x]},
		})
	}
	slices.SortFunc(leaves, sortLogLeaf)

	// Identify the leaves that we have only the timestamp for.
	empty := make([]uint64, 0)
	for _, leaf := range leaves {
		if leaf.PrefixTree == nil {
			empty = append(empty, leaf.position)
		}
	}

	// In-fill missing prefix tree root values.
	prefixTrees, err := dp.handle.GetPrefixTrees(empty)
	if err != nil {
		return nil, err
	}
	for i, leaf := range leaves {
		if leaf.PrefixTree == nil {
			leaves[i].PrefixTree = prefixTrees[0]
			prefixTrees = prefixTrees[1:]
		}
	}

	return leaves, nil
}

type proofResult struct {
	frontier   [][]byte                    // The frontier for the user to retain.
	additional [][]byte                    // The additional frontier, if requested.
	logEntries map[uint64]structs.LogEntry // Log entries for the user to retain.
}

// Finish takes as input the current tree size `n`, an optional additional tree
// size `nP`, and the optional previous tree size `m`. It returns the result of
// the proof evaluation that was done.
func (dp *dataProvider) Finish(n uint64, nP, m *uint64) (*proofResult, error) {
	leaves, err := dp.inspectedLeaves()
	if err != nil {
		return nil, err
	}

	// Convert leaves slice into a slice of log entry positions and a slice of
	// log entry hashes.
	positions := make([]uint64, len(leaves))
	values := make([][]byte, len(leaves))

	hasher := dp.cs.Hash()
	for i, leaf := range leaves {
		buf := &bytes.Buffer{}
		if err := leaf.Marshal(buf); err != nil {
			return nil, err
		} else if _, err := hasher.Write(buf.Bytes()); err != nil {
			return nil, err
		}
		positions[i] = leaf.position
		values[i] = hasher.Sum(nil)
		hasher.Reset()
	}

	// Evaluate the inclusion proof to find the log's new frontier.
	proof, err := dp.handle.Finish()
	if err != nil {
		return nil, err
	}
	verifier := log.NewVerifier(dp.cs)
	if m != nil {
		if err := verifier.Retain(*m, dp.fullSubtrees); err != nil {
			return nil, err
		}
	}
	frontier, additional, err := verifier.Evaluate(positions, n, nP, values, proof)
	if err != nil {
		return nil, err
	}

	// Build the set of log entries to retain.
	logEntries := make(map[uint64]structs.LogEntry)
	for _, x := range math.Frontier(n) {
		ts, ok := dp.timestamps[x]
		if !ok {
			return nil, errors.New("expected timestamp not retained")
		}
		prefixTree, ok := dp.prefixTrees[x]
		if !ok {
			return nil, errors.New("expected prefix tree root not retained")
		}
		logEntries[x] = structs.LogEntry{Timestamp: ts, PrefixTree: prefixTree}
	}

	return &proofResult{frontier, additional, logEntries}, nil
}

// Output takes as input the current tree size `n`, an optional additional tree
// size `nP`, and the optional previous tree size `m`. It returns the produced
// CombinedTreeProof structure.
func (dp *dataProvider) Output(n uint64, nP, m *uint64) (*structs.CombinedTreeProof, error) {
	leaves, err := dp.inspectedLeaves()
	if err != nil {
		return nil, err
	}
	positions := make([]uint64, len(leaves))
	for i, leaf := range leaves {
		positions[i] = leaf.position
	}
	return dp.handle.Output(positions, n, nP, m)
}

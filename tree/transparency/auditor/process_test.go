package auditor

import (
	"bytes"
	"context"
	"crypto/rand"
	"slices"
	"strings"
	"testing"

	"github.com/Bren2010/katie/db"
	"github.com/Bren2010/katie/tree/log"
	"github.com/Bren2010/katie/tree/prefix"
	"github.com/Bren2010/katie/tree/transparency/algorithms"
	"github.com/Bren2010/katie/tree/transparency/math"
	"github.com/Bren2010/katie/tree/transparency/structs"
	"github.com/Bren2010/katie/tree/transparency/test"
)

// window is the Reasonable Monitoring Window used by these tests. Timestamps
// are chosen relative to it so that which log entries are distinguished is
// known exactly:
//
//   - slow(i) spaces entries one window apart. The previous rightmost
//     distinguished log entry of entry i is then always entry i-1.
//   - fast() gives every entry the same timestamp. The previous rightmost
//     distinguished log entry is entry 3 for entries 4 through 7, and entry 7
//     for entries 8 through 15.
//   - A timestamp of zero means that no log entry is ever distinguished.
//
// Tests assert these facts with expectPrevDLE before relying on them.
const window = 100

func slow(i uint64) uint64 { return (i + 1) * window }
func fast() uint64         { return window }

// simLog simulates the parts of a Transparency Log that an auditor observes: a
// prefix tree that's modified once per log entry, and a log tree whose leaves
// commit to each log entry's timestamp and prefix tree root.
type simLog struct {
	t      *testing.T
	config *structs.PublicConfig
	prefix *prefix.Tree

	timestamps   []uint64   // Timestamp of each log entry.
	prefixRoots  [][]byte   // Prefix tree root of each log entry.
	fullSubtrees [][][]byte // Log tree full subtrees after each log entry.
	added        [][][]byte // VRF outputs added in each log entry.
}

func newSimLog(t *testing.T, config *structs.PublicConfig) *simLog {
	store := db.NewTransparencyStore(context.Background(), db.NewMemoryKeyValueStore(), false)
	return &simLog{
		t:      t,
		config: config,
		prefix: prefix.NewTree(config.Suite, store.PrefixStore()),
	}
}

func (s *simLog) size() uint64 { return uint64(len(s.timestamps)) }

// leaf returns the i-th VRF output that was added in log entry `pos`.
func (s *simLog) leaf(pos uint64, i int) []byte { return s.added[pos][i] }

// proposal is a log entry that has been built but not yet appended to the
// simulated log.
type proposal struct {
	update *structs.AuditorUpdate
	root   []byte
	added  [][]byte
}

// propose builds the next log entry with the given timestamp, `numAdd` new
// random prefix tree entries, and the given removals. It does not append the
// log entry, so a rejected proposal can be followed by a different one for the
// same position.
func (s *simLog) propose(timestamp uint64, numAdd int, remove ...[]byte) *proposal {
	s.t.Helper()

	add := make([]prefix.Entry, numAdd)
	for i := range add {
		add[i] = prefix.Entry{VrfOutput: randomHash(), Commitment: randomHash()}
	}
	slices.SortFunc(add, func(a, b prefix.Entry) int { return bytes.Compare(a.VrfOutput, b.VrfOutput) })
	remove = slices.Clone(remove)
	slices.SortFunc(remove, bytes.Compare)

	mut, err := s.prefix.Mutate(s.size(), add, remove)
	if err != nil {
		s.t.Fatal(err)
	}
	removed := make([]prefix.Entry, len(remove))
	for i, vrfOutput := range remove {
		removed[i] = prefix.Entry{VrfOutput: vrfOutput, Commitment: mut.Commitments[i]}
	}

	vrfOutputs := make([][]byte, len(add))
	for i, entry := range add {
		vrfOutputs[i] = entry.VrfOutput
	}
	return &proposal{
		update: &structs.AuditorUpdate{
			Timestamp: timestamp,
			Added:     add,
			Removed:   removed,
			Leaves:    mut.Leaves,
			Proof:     mut.Proof,
		},
		root:  mut.Root,
		added: vrfOutputs,
	}
}

// accept appends a proposed log entry to the simulated log.
func (s *simLog) accept(p *proposal) {
	s.t.Helper()

	entry := structs.LogEntry{Timestamp: p.update.Timestamp, PrefixTree: p.root}
	leaf, err := entry.Hash(s.config.Suite)
	if err != nil {
		s.t.Fatal(err)
	}
	var prev [][]byte
	if n := len(s.fullSubtrees); n > 0 {
		prev = s.fullSubtrees[n-1]
	}
	next, err := log.Append(s.config.Suite, s.size(), prev, leaf)
	if err != nil {
		s.t.Fatal(err)
	}

	s.timestamps = append(s.timestamps, p.update.Timestamp)
	s.prefixRoots = append(s.prefixRoots, p.root)
	s.fullSubtrees = append(s.fullSubtrees, next)
	s.added = append(s.added, p.added)
}

// append builds and appends the next log entry, and returns its AuditorUpdate.
func (s *simLog) append(timestamp uint64, numAdd int, remove ...[]byte) *structs.AuditorUpdate {
	s.t.Helper()
	p := s.propose(timestamp, numAdd, remove...)
	s.accept(p)
	return p.update
}

// initState returns the values that an auditor starting at log entry `n` is
// initialized with.
func (s *simLog) initState(n uint64) (fullSubtrees [][]byte, timestamps []uint64, prefixTree []byte) {
	for _, x := range math.Frontier(n) {
		timestamps = append(timestamps, s.timestamps[x])
	}
	return slices.Clone(s.fullSubtrees[n-1]), timestamps, slices.Clone(s.prefixRoots[n-1])
}

// expectPrevDLE checks that, if the next log entry has the given timestamp,
// the previous rightmost distinguished log entry is `want`. A negative `want`
// means that there should be none.
func (s *simLog) expectPrevDLE(timestamp uint64, want int) {
	s.t.Helper()

	entries := make(map[uint64]structs.LogEntry)
	for i, ts := range s.timestamps {
		entries[uint64(i)] = structs.LogEntry{Timestamp: ts}
	}
	entries[s.size()] = structs.LogEntry{Timestamp: timestamp}

	provider := algorithms.NewDataProvider(s.config.Suite, nil)
	if err := provider.AddRetained(nil, entries); err != nil {
		s.t.Fatal(err)
	}
	got, err := algorithms.PreviousRightmost(s.config, s.size()+1, provider)
	if err != nil {
		s.t.Fatal(err)
	}
	if want < 0 && got != nil {
		s.t.Fatalf("test premise broken: log entry %v has previous distinguished log entry %v, want none", s.size(), *got)
	} else if want >= 0 && (got == nil || *got != uint64(want)) {
		s.t.Fatalf("test premise broken: log entry %v has previous distinguished log entry %v, want %v", s.size(), got, want)
	}
}

// checkTreeHead verifies that an auditor tree head is correctly signed over
// the simulated log's root, and has the timestamp of its rightmost log entry.
func (s *simLog) checkTreeHead(th *structs.AuditorTreeHead) {
	s.t.Helper()

	if th.TreeSize == 0 || th.TreeSize > s.size() {
		s.t.Fatalf("auditor tree head has unexpected tree size %v", th.TreeSize)
	} else if th.Timestamp != s.timestamps[th.TreeSize-1] {
		s.t.Fatal("auditor tree head has unexpected timestamp")
	}
	root, err := log.Root(s.config.Suite, th.TreeSize, s.fullSubtrees[th.TreeSize-1])
	if err != nil {
		s.t.Fatal(err)
	}
	tbs, err := structs.Marshal(&structs.AuditorTreeHeadTBS{
		Config:    s.config,
		Timestamp: th.Timestamp,
		TreeSize:  th.TreeSize,
		Root:      root,
	})
	if err != nil {
		s.t.Fatal(err)
	} else if !s.config.AuditorPublicKey.Verify(tbs, th.Signature) {
		s.t.Fatal("auditor tree head signature does not verify over the log root")
	}
}

func randomHash() []byte {
	out := make([]byte, 32)
	rand.Read(out)
	return out
}

// newTestAuditor returns a simulated log and a fresh auditor for it, with the
// given starting position.
func newTestAuditor(t *testing.T, startPos uint64, allowPruning bool) (*simLog, *Auditor) {
	t.Helper()

	config, auditorKey := test.ConfigWithAuditor(t)
	config.ReasonableMonitoringWindow = window
	config.AuditorStartPos = startPos
	public := config.Public()

	auditor, err := NewAuditor(public, auditorKey, db.NewMemoryAuditorStore(), allowPruning)
	if err != nil {
		t.Fatal(err)
	}
	return newSimLog(t, public), auditor
}

// reload returns a new auditor that loads its state from the same database.
func reload(t *testing.T, a *Auditor) *Auditor {
	t.Helper()
	out, err := NewAuditor(a.config, a.auditorKey, a.tx, a.allowPruning)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func mustProcess(t *testing.T, a *Auditor, update *structs.AuditorUpdate) {
	t.Helper()
	if err := a.Process(update); err != nil {
		t.Fatal(err)
	}
}

func mustCommit(t *testing.T, a *Auditor) *structs.AuditorTreeHead {
	t.Helper()
	th, err := a.Commit()
	if err != nil {
		t.Fatal(err)
	}
	return th
}

func expectErr(t *testing.T, err error, contains string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected an error containing %q, got none", contains)
	} else if !strings.Contains(err.Error(), contains) {
		t.Fatalf("expected an error containing %q, got: %v", contains, err)
	}
}

const notEligible = "not eligible for removal"

// TestProcessAndCommit checks that the auditor's tree heads verify over the
// real log root after every log entry, and that it continues correctly after
// being reloaded from its database.
func TestProcessAndCommit(t *testing.T) {
	sim, auditor := newTestAuditor(t, 0, true)

	for i := range uint64(6) {
		mustProcess(t, auditor, sim.append(slow(i), 3))
		sim.checkTreeHead(mustCommit(t, auditor))
	}

	// Committing again without processing anything returns the same head.
	first := mustCommit(t, auditor)
	second := mustCommit(t, auditor)
	if !bytes.Equal(first.Signature, second.Signature) {
		t.Fatal("repeated commit produced a different tree head")
	}

	auditor = reload(t, auditor)
	for i := uint64(6); i < 10; i++ {
		mustProcess(t, auditor, sim.append(slow(i), 3))
	}
	sim.checkTreeHead(mustCommit(t, auditor))
}

// TestCommitRequiresProcessedEntry checks that an auditor that hasn't
// processed anything refuses to issue a tree head.
func TestCommitRequiresProcessedEntry(t *testing.T) {
	_, auditor := newTestAuditor(t, 0, true)
	if _, err := auditor.Commit(); err == nil {
		t.Fatal("auditor committed without processing any log entries")
	}
}

// TestRejectsDecreasingTimestamp checks that a log entry's timestamp can't be
// less than that of the previous log entry.
func TestRejectsDecreasingTimestamp(t *testing.T) {
	sim, auditor := newTestAuditor(t, 0, true)
	mustProcess(t, auditor, sim.append(slow(1), 1))

	err := auditor.Process(sim.propose(slow(0), 1).update)
	expectErr(t, err, "timestamp")
}

// TestRejectsSkippedEntry checks that the auditor rejects an update whose
// proof isn't from the auditor's current prefix tree.
func TestRejectsSkippedEntry(t *testing.T) {
	sim, auditor := newTestAuditor(t, 0, true)
	mustProcess(t, auditor, sim.append(slow(0), 2))
	sim.append(slow(1), 2) // Never shown to the auditor.

	err := auditor.Process(sim.append(slow(2), 2))
	expectErr(t, err, "prefix tree root does not match")
}

// TestFailedProcessLeavesStateUnchanged checks that a rejected update doesn't
// modify the auditor's state, and that the auditor can then process the
// correct update.
func TestFailedProcessLeavesStateUnchanged(t *testing.T) {
	sim, auditor := newTestAuditor(t, 0, true)
	for i := range uint64(3) {
		mustProcess(t, auditor, sim.append(slow(i), 2))
	}
	before, err := auditor.state.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	// Tamper with the proof so that it evaluates to the wrong prior root.
	update := sim.append(slow(3), 2)
	tampered := *update
	tampered.Proof.Elements = slices.Clone(update.Proof.Elements)
	tampered.Proof.Elements[0] = randomHash()
	if err := auditor.Process(&tampered); err == nil {
		t.Fatal("auditor accepted a tampered proof")
	}

	after, err := auditor.state.Marshal()
	if err != nil {
		t.Fatal(err)
	} else if !bytes.Equal(before, after) {
		t.Fatal("rejected update modified the auditor's state")
	}

	mustProcess(t, auditor, update)
	sim.checkTreeHead(mustCommit(t, auditor))
}

// TestRemovalRequiresPruning checks that an auditor that doesn't allow pruning
// rejects every removal, and doesn't retain inserted VRF outputs.
func TestRemovalRequiresPruning(t *testing.T) {
	sim, auditor := newTestAuditor(t, 0, false)
	for i := range uint64(3) {
		mustProcess(t, auditor, sim.append(slow(i), 2))
	}
	if len(auditor.state.inserted) != 0 {
		t.Fatal("auditor retained inserted vrf outputs without pruning enabled")
	}

	sim.expectPrevDLE(slow(3), 2)
	err := auditor.Process(sim.propose(slow(3), 0, sim.leaf(0, 0)).update)
	expectErr(t, err, notEligible)
}

// TestRemovalRequiresDistinguishedEntry checks that nothing can be removed
// before there's a distinguished log entry.
func TestRemovalRequiresDistinguishedEntry(t *testing.T) {
	sim, auditor := newTestAuditor(t, 0, true)
	for range 4 {
		mustProcess(t, auditor, sim.append(0, 2))
	}

	sim.expectPrevDLE(0, -1)
	err := auditor.Process(sim.propose(0, 0, sim.leaf(0, 0)).update)
	expectErr(t, err, notEligible)
}

// TestRemovalEligibility checks that a leaf can be removed if and only if it
// was added at or before the previous rightmost distinguished log entry.
func TestRemovalEligibility(t *testing.T) {
	sim, auditor := newTestAuditor(t, 0, true)
	for range 5 {
		mustProcess(t, auditor, sim.append(fast(), 2))
	}

	// Log entry 5: the previous distinguished log entry is 3.
	sim.expectPrevDLE(fast(), 3)
	err := auditor.Process(sim.propose(fast(), 0, sim.leaf(4, 0)).update)
	expectErr(t, err, notEligible)
	mustProcess(t, auditor, sim.append(fast(), 1, sim.leaf(3, 0)))

	// Log entry 6: still 3. A leaf added in entry 5 or after is too recent,
	// and the auditor must remember this across more than one log entry.
	sim.expectPrevDLE(fast(), 3)
	err = auditor.Process(sim.propose(fast(), 0, sim.leaf(4, 1)).update)
	expectErr(t, err, notEligible)
	err = auditor.Process(sim.propose(fast(), 0, sim.leaf(5, 0)).update)
	expectErr(t, err, notEligible)
	err = auditor.Process(sim.propose(fast(), 0, sim.leaf(0, 0), sim.leaf(4, 1)).update)
	expectErr(t, err, notEligible)
	mustProcess(t, auditor, sim.append(fast(), 1, sim.leaf(0, 0), sim.leaf(2, 0)))

	mustProcess(t, auditor, sim.append(fast(), 1))

	// Log entry 8: the previous distinguished log entry moves to 7, which
	// makes the leaves from entries 4 through 7 eligible.
	sim.expectPrevDLE(fast(), 7)
	mustProcess(t, auditor, sim.append(fast(), 1, sim.leaf(4, 0), sim.leaf(7, 0)))

	// Log entry 9: still 7, so the leaf from entry 8 is too recent.
	sim.expectPrevDLE(fast(), 7)
	err = auditor.Process(sim.propose(fast(), 0, sim.leaf(8, 0)).update)
	expectErr(t, err, notEligible)

	sim.checkTreeHead(mustCommit(t, auditor))
}

// TestRemovalOfReaddedOutput checks that a VRF output that's removed and added
// again in the same log entry is treated as newly added.
func TestRemovalOfReaddedOutput(t *testing.T) {
	sim, auditor := newTestAuditor(t, 0, true)
	for range 5 {
		mustProcess(t, auditor, sim.append(fast(), 2))
	}
	vrfOutput := sim.leaf(0, 0)

	// Log entry 5 replaces the leaf with a new commitment.
	sim.expectPrevDLE(fast(), 3)
	p := sim.propose(fast(), 0, vrfOutput)
	p.update.Added = []prefix.Entry{{VrfOutput: vrfOutput, Commitment: randomHash()}}
	mut, err := sim.prefix.Mutate(sim.size(), p.update.Added, [][]byte{vrfOutput})
	if err != nil {
		t.Fatal(err)
	}
	p.update.Leaves, p.update.Proof, p.root = mut.Leaves, mut.Proof, mut.Root
	p.added = [][]byte{vrfOutput}
	mustProcess(t, auditor, p.update)
	sim.accept(p)

	// Log entry 6 can't remove it, because it was re-added after entry 3.
	sim.expectPrevDLE(fast(), 3)
	err = auditor.Process(sim.propose(fast(), 0, vrfOutput).update)
	expectErr(t, err, notEligible)
}

// TestRemovalCheckSurvivesReload checks that the auditor remembers recently
// inserted VRF outputs after being reloaded from its database.
func TestRemovalCheckSurvivesReload(t *testing.T) {
	sim, auditor := newTestAuditor(t, 0, true)
	for range 5 {
		mustProcess(t, auditor, sim.append(fast(), 2))
	}
	mustCommit(t, auditor)
	auditor = reload(t, auditor)

	sim.expectPrevDLE(fast(), 3)
	err := auditor.Process(sim.propose(fast(), 0, sim.leaf(4, 0)).update)
	expectErr(t, err, notEligible)
	mustProcess(t, auditor, sim.append(fast(), 0, sim.leaf(3, 0)))
}

// TestNonZeroStartRequiresInitialize checks that an auditor that starts partway
// through the log refuses to do anything until it's initialized.
func TestNonZeroStartRequiresInitialize(t *testing.T) {
	sim, auditor := newTestAuditor(t, 4, true)
	for i := range uint64(5) {
		sim.append(slow(i), 2)
	}

	err := auditor.Process(sim.propose(slow(5), 1).update)
	expectErr(t, err, "not initialized")
	if _, err := auditor.Commit(); err == nil {
		t.Fatal("uninitialized auditor issued a tree head")
	}
}

// TestInitializeValidation checks that Initialize rejects malformed input, and
// can't be used to overwrite existing state.
func TestInitializeValidation(t *testing.T) {
	const start = 5

	sim, _ := newTestAuditor(t, start, true)
	for i := range uint64(start) {
		sim.append(slow(i), 2)
	}
	fullSubtrees, timestamps, prefixTree := sim.initState(start)
	if len(fullSubtrees) < 2 || len(timestamps) < 2 {
		t.Fatal("test premise broken: need at least two full subtrees and timestamps")
	}

	reversed := slices.Clone(timestamps)
	slices.Reverse(reversed)

	cases := []struct {
		name         string
		fullSubtrees [][]byte
		timestamps   []uint64
		prefixTree   []byte
	}{
		{"missing full subtree", fullSubtrees[1:], timestamps, prefixTree},
		{"extra full subtree", append(slices.Clone(fullSubtrees), randomHash()), timestamps, prefixTree},
		{"short full subtree", [][]byte{fullSubtrees[0], fullSubtrees[1][1:]}, timestamps, prefixTree},
		{"missing timestamp", fullSubtrees, timestamps[1:], prefixTree},
		{"decreasing timestamps", fullSubtrees, reversed, prefixTree},
		{"short prefix tree", fullSubtrees, timestamps, prefixTree[1:]},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, auditor := newTestAuditor(t, start, true)
			if err := auditor.Initialize(c.fullSubtrees, c.timestamps, c.prefixTree); err == nil {
				t.Fatal("auditor accepted malformed initial state")
			} else if auditor.state != nil {
				t.Fatal("rejected initial state was retained")
			}
		})
	}

	t.Run("already initialized", func(t *testing.T) {
		_, auditor := newTestAuditor(t, start, true)
		if err := auditor.Initialize(fullSubtrees, timestamps, prefixTree); err != nil {
			t.Fatal(err)
		} else if err := auditor.Initialize(fullSubtrees, timestamps, prefixTree); err == nil {
			t.Fatal("auditor was initialized twice")
		}
	})

	t.Run("already processed", func(t *testing.T) {
		sim, auditor := newTestAuditor(t, 0, true)
		mustProcess(t, auditor, sim.append(slow(0), 1))
		if err := auditor.Initialize(nil, nil, make([]byte, 32)); err == nil {
			t.Fatal("auditor was initialized after processing a log entry")
		}
	})
}

// newStartedAuditor returns an auditor that starts at log entry `start`, and a
// simulated log with `start` log entries that the auditor is initialized with.
func newStartedAuditor(t *testing.T, start uint64, timestamp func(i uint64) uint64) (*simLog, *Auditor) {
	t.Helper()

	sim, auditor := newTestAuditor(t, start, true)
	for i := range start {
		sim.append(timestamp(i), 2)
	}
	if err := auditor.Initialize(sim.initState(start)); err != nil {
		t.Fatal(err)
	}
	return sim, auditor
}

// TestNonZeroStartProcessAndCommit checks that an auditor starting partway
// through the log issues tree heads that cover the whole log.
func TestNonZeroStartProcessAndCommit(t *testing.T) {
	sim, auditor := newStartedAuditor(t, 5, slow)

	for i := uint64(5); i < 11; i++ {
		mustProcess(t, auditor, sim.append(slow(i), 3))
		sim.checkTreeHead(mustCommit(t, auditor))
	}

	auditor = reload(t, auditor)
	mustProcess(t, auditor, sim.append(slow(11), 3))
	sim.checkTreeHead(mustCommit(t, auditor))
}

// TestNonZeroStartRejectsWrongPrefixTree checks that the first update is
// checked against the prefix tree root the auditor was initialized with.
func TestNonZeroStartRejectsWrongPrefixTree(t *testing.T) {
	const start = 5

	sim, auditor := newTestAuditor(t, start, true)
	for i := range uint64(start) {
		sim.append(slow(i), 2)
	}
	fullSubtrees, timestamps, _ := sim.initState(start)
	if err := auditor.Initialize(fullSubtrees, timestamps, sim.prefixRoots[start-2]); err != nil {
		t.Fatal(err)
	}

	err := auditor.Process(sim.append(slow(start), 1))
	expectErr(t, err, "prefix tree root does not match")
}

// TestNonZeroStartRejectsDecreasingTimestamp checks that the first update
// processed by an auditor that starts partway through the log can't have a
// timestamp less than that of the log entry before it.
func TestNonZeroStartRejectsDecreasingTimestamp(t *testing.T) {
	const start = 4
	sim, auditor := newStartedAuditor(t, start, slow)

	update := sim.propose(slow(start-1)-1, 1).update
	err := func() (err error) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("auditor panicked instead of rejecting the update: %v", r)
			}
		}()
		return auditor.Process(update)
	}()
	expectErr(t, err, "timestamp")
}

// TestNonZeroStartCommitRequiresProcessedEntry checks that an auditor that
// starts partway through the log doesn't issue a tree head until it has
// processed a log entry. Otherwise it would sign a tree head covering log
// entries that it never verified.
func TestNonZeroStartCommitRequiresProcessedEntry(t *testing.T) {
	_, auditor := newStartedAuditor(t, 4, slow)
	if th, err := auditor.Commit(); err == nil {
		t.Fatalf("auditor signed a tree head of size %v without processing any log entries", th.TreeSize)
	}
}

// TestNonZeroStartRemovalBoundary checks that removals are rejected while the
// previous rightmost distinguished log entry is before the auditor's starting
// position, and accepted once it's at the starting position.
func TestNonZeroStartRemovalBoundary(t *testing.T) {
	const start = 4
	sim, auditor := newStartedAuditor(t, start, slow)

	// Log entry 4: the previous distinguished log entry is 3, which the
	// auditor didn't process.
	sim.expectPrevDLE(slow(4), start-1)
	err := auditor.Process(sim.propose(slow(4), 0, sim.leaf(1, 0)).update)
	expectErr(t, err, notEligible)
	mustProcess(t, auditor, sim.append(slow(4), 2))

	// Log entry 5: the previous distinguished log entry is 4, the first one
	// the auditor processed. A leaf from before the auditor started, and a
	// leaf added in entry 4 itself, are both eligible.
	sim.expectPrevDLE(slow(5), start)
	mustProcess(t, auditor, sim.append(slow(5), 1, sim.leaf(1, 0), sim.leaf(4, 0)))

	sim.checkTreeHead(mustCommit(t, auditor))
}

// TestNonZeroStartRemovalWindow checks removal eligibility over a longer
// stretch where the previous rightmost distinguished log entry doesn't change.
func TestNonZeroStartRemovalWindow(t *testing.T) {
	const start = 4
	sim, auditor := newStartedAuditor(t, start, func(uint64) uint64 { return fast() })

	// Log entries 4 through 7: the previous distinguished log entry is 3, so
	// nothing can be removed, even leaves from before the auditor started.
	for range 4 {
		sim.expectPrevDLE(fast(), start-1)
		err := auditor.Process(sim.propose(fast(), 0, sim.leaf(0, 0)).update)
		expectErr(t, err, notEligible)
		mustProcess(t, auditor, sim.append(fast(), 2))
	}

	// Log entry 8: the previous distinguished log entry is 7. Leaves from
	// before the auditor started and leaves the auditor saw added are eligible.
	sim.expectPrevDLE(fast(), 7)
	mustProcess(t, auditor, sim.append(fast(), 1, sim.leaf(0, 0), sim.leaf(5, 0), sim.leaf(7, 0)))

	// Log entry 9: still 7, so the leaf from entry 8 is too recent.
	sim.expectPrevDLE(fast(), 7)
	err := auditor.Process(sim.propose(fast(), 0, sim.leaf(8, 0)).update)
	expectErr(t, err, notEligible)
	mustProcess(t, auditor, sim.append(fast(), 0, sim.leaf(2, 0), sim.leaf(6, 1)))

	sim.checkTreeHead(mustCommit(t, auditor))
}

// TestProcessEmptyUpdate checks that the auditor accepts log entries that don't
// modify the prefix tree, both when the prefix tree is empty and when it isn't,
// and that it still verifies the prefix tree root of such entries.
func TestProcessEmptyUpdate(t *testing.T) {
	sim, auditor := newTestAuditor(t, 0, true)

	mustProcess(t, auditor, sim.append(slow(0), 0))
	mustProcess(t, auditor, sim.append(slow(1), 2))
	mustProcess(t, auditor, sim.append(slow(2), 0))
	sim.checkTreeHead(mustCommit(t, auditor))

	// An empty update that claims the wrong prior root is rejected.
	update := sim.propose(slow(3), 0).update
	tampered := *update
	tampered.Proof.Elements = [][]byte{randomHash()}
	if err := auditor.Process(&tampered); err == nil {
		t.Fatal("auditor accepted an empty update with the wrong prefix tree root")
	}

	// An empty update can't move any leaves.
	tampered = *update
	tampered.Leaves = []prefix.Entry{{VrfOutput: sim.leaf(1, 0), Commitment: randomHash()}}
	if err := auditor.Process(&tampered); err == nil {
		t.Fatal("auditor accepted an empty update that moves a leaf")
	}

	mustProcess(t, auditor, update)
	sim.accept(&proposal{update: update, root: sim.prefixRoots[sim.size()-1]})
	sim.checkTreeHead(mustCommit(t, auditor))
}

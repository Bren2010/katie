package transparency

import (
	"cmp"
	"errors"
	"slices"

	"github.com/Bren2010/katie/crypto/commitments"
	"github.com/Bren2010/katie/tree/log"
	"github.com/Bren2010/katie/tree/transparency/algorithms"
	"github.com/Bren2010/katie/tree/transparency/math"
	"github.com/Bren2010/katie/tree/transparency/structs"
)

// verifier abstracts CombinedTreeProof verification to make it slightly simpler
// for the methods on Client.
type verifier struct {
	config *structs.PublicConfig
	state  *structs.ClientState
	fth    structs.FullTreeHead

	handle   *algorithms.ReceivedProofHandle
	provider *algorithms.DataProvider
}

func newVerifier(
	config *structs.PublicConfig,
	state *structs.ClientState,
	fth structs.FullTreeHead,
	proof structs.CombinedTreeProof,
) (*verifier, error) {
	if fth.TreeHead == nil && state == nil {
		return nil, errors.New("no tree head found")
	}

	handle := algorithms.NewReceivedProofHandle(config.Suite, proof)
	provider := algorithms.NewDataProvider(config.Suite, handle)
	if state != nil {
		err := provider.AddRetained(state.FullSubtrees, state.LogEntries)
		if err != nil {
			return nil, err
		}
	}

	return &verifier{config, state, fth, handle, provider}, nil
}

func (v *verifier) n() uint64 {
	if v.fth.TreeHead != nil {
		return v.fth.TreeHead.TreeSize
	}
	return *v.m()
}

func (v *verifier) nP() *uint64 {
	if v.fth.AuditorTreeHead != nil {
		return &v.fth.AuditorTreeHead.TreeSize
	}
	return nil
}

func (v *verifier) m() *uint64 {
	if v.state != nil {
		return &v.state.TreeHead.TreeSize
	}
	return nil
}

// addLabelState adds all of the retained VRF outputs and commitments to the
// ProofHandle so that they can be used in proof verification. Manually computed
// commitments are provided in `manual`.
func (v *verifier) addLabelState(
	state *structs.ClientLabelState,
	manual map[uint32][]byte,
) error {
	for _, entry := range state.Versions {
		commitment := entry.Commitment
		if commitment == nil {
			commitment = manual[entry.Version]
		}
		err := v.handle.AddVersion(entry.Version, entry.VrfOutput, commitment)
		if err != nil {
			return err
		}
	}
	return nil
}

// processLadder converts all of the VRF proofs in `ladder` into VRF outputs and
// adds them to the ProofHandle. Any manually computed commitments that should
// be used for a label version are provided in `manual`.
func (v *verifier) processLadder(
	label []byte,
	ladder []structs.BinaryLadderStep,
	vers []uint32,
	manual map[uint32][]byte,
) error {
	if len(ladder) != len(vers) {
		return errors.New("incorrect number of binary ladder steps provided")
	}

	for i, ver := range vers {
		input, err := structs.Marshal(&structs.VrfInput{Label: label, Version: ver})
		if err != nil {
			return err
		}
		vrfOutput, err := v.config.VrfKey.Verify(input, ladder[i].Proof)
		if err != nil {
			return err
		}

		commitment, ok := manual[ver]
		if ok && ladder[i].Commitment != nil {
			return errors.New("commitment provided when not expected")
		} else if !ok {
			commitment = ladder[i].Commitment
		}

		if err := v.handle.AddVersion(ver, vrfOutput, commitment); err != nil {
			return err
		}
	}

	return nil
}

func (v *verifier) updateView(now uint64) error {
	if err := algorithms.UpdateView(v.config, v.n(), v.m(), v.provider); err != nil {
		return err
	}
	return algorithms.VerifyFreshness(v.config, v.n(), now, v.provider)
}

func (v *verifier) greatestVersionSearch(ver uint32) (uint64, error) {
	return algorithms.GreatestVersionSearch(v.config, ver, v.n(), v.provider)
}

func (v *verifier) fixedVersionSearch(ver uint32) (uint64, error) {
	return algorithms.FixedVersionSearch(v.config, ver, v.n(), v.provider)
}

func (v *verifier) monitor() (*algorithms.Monitor, error) {
	return algorithms.NewMonitor(v.config, v.n(), v.provider)
}

func (v *verifier) rightmostDistinguished() (*uint64, error) {
	return algorithms.RightmostDistinguished(v.config, v.n(), v.provider)
}

// TODO: What about monitoring?

func (v *verifier) verifyTreeHead(root, rootP []byte) error {
	if v.fth.TreeHead == nil {
		if v.state == nil {
			return errors.New("same tree head not allowed when client has no state")
		}
		// Note: Verifying that the rightmost timestamp is within the bounds set
		// by MaxAhead and MaxBehind is done in updateView().
		return nil
	}

	// Verify the size and signature on the tree head.
	if v.m() != nil && v.n() <= *v.m() {
		return errors.New("provided tree size is not greater than advertised")
	}
	tbs, err := structs.Marshal(&structs.TreeHeadTBS{
		Config:   v.config,
		TreeSize: v.n(),
		Root:     root,
	})
	if err != nil {
		return err
	}
	ok := v.config.SignatureKey.Verify(tbs, v.fth.TreeHead.Signature)
	if !ok {
		return errors.New("failed to verify tree head signature")
	} else if v.fth.AuditorTreeHead == nil {
		return nil
	}

	// Verify size and signature of the auditor tree head.
	if v.state != nil {
		if v.state.AuditorTreeHead == nil {
			return errors.New("missing previous auditor tree head")
		} else if v.state.AuditorTreeHead.TreeSize < v.config.AuditorStartPos {
			return errors.New("previous auditor tree size does not cover new auditor start position")
		}
	}
	rightmost, err := v.provider.GetTimestamp(v.n() - 1)
	if err != nil {
		return err
	}
	auditorTreeHead := v.fth.AuditorTreeHead
	if auditorTreeHead.Timestamp > rightmost {
		return errors.New("auditor timestamp is greater than rightmost log entry timestamp")
	} else if rightmost-auditorTreeHead.Timestamp > v.config.MaxAuditorLag {
		return errors.New("auditor timestamp is too far behind rightmost log entry timestamp")
	} else if auditorTreeHead.TreeSize > v.n() {
		return errors.New("auditor tree size is greater than transparency log tree size")
	}

	tbs, err = structs.Marshal(&structs.AuditorTreeHeadTBS{
		Config:    v.config,
		Timestamp: auditorTreeHead.Timestamp,
		TreeSize:  auditorTreeHead.TreeSize,
		Root:      rootP,
	})
	if err != nil {
		return err
	}
	ok = v.config.AuditorPublicKey.Verify(tbs, auditorTreeHead.Signature)
	if !ok {
		return errors.New("failed to verify auditor signature")
	}

	return nil
}

// finish computes the final tree root, verifies the transparency log's
// signature over it, and returns the new state for the client to retain.
func (v *verifier) finish() (*structs.ClientState, error) {
	result, err := v.provider.Finish(v.n(), v.nP(), v.m())
	if err != nil {
		return nil, err
	}

	// Compute a candidate root value for the tree and, if needed, the subtree
	// signed by the auditor.
	root, err := log.Root(v.config.Suite, v.n(), result.FullSubtrees)
	if err != nil {
		return nil, err
	}

	var rootP []byte
	if nP := v.nP(); nP != nil {
		rootP, err = log.Root(v.config.Suite, *nP, result.Additional)
		if err != nil {
			return nil, err
		}
	}

	// Verify the signature on the tree head.
	err = v.verifyTreeHead(root, rootP)
	if err != nil {
		return nil, err
	}

	// Compute and return the updated client state. If the Transparency Log
	// reused the previous tree head, the client keeps the previous tree head
	// and auditor tree head. Note that verifyTreeHead has already checked that
	// the client has state in that case.
	updated := &structs.ClientState{
		FullSubtrees: result.FullSubtrees,
		LogEntries:   result.LogEntries,
	}
	if v.fth.TreeHead != nil {
		updated.TreeHead = *v.fth.TreeHead
		updated.AuditorTreeHead = v.fth.AuditorTreeHead
	} else {
		updated.TreeHead = v.state.TreeHead
		updated.AuditorTreeHead = v.state.AuditorTreeHead
	}
	return updated, nil
}

func getLast(state *structs.ClientState) *uint64 {
	if state == nil {
		return nil
	}
	return &state.TreeHead.TreeSize
}

func getDistinguished(config *structs.PublicConfig, state *structs.ClientState) (uint64, error) {
	if state == nil {
		return 0, errors.New("unable to make request with no state")
	}

	provider := algorithms.NewDataProvider(config.Suite, nil)
	provider.AddRetained(nil, state.LogEntries)
	rightmostDLE, err := algorithms.RightmostDistinguished(config, state.TreeHead.TreeSize, provider)
	if err != nil {
		return 0, err
	} else if rightmostDLE == nil {
		return 0, errors.New("unable to make request if no distinguished log entries exist")
	}

	return *rightmostDLE, nil
}

// verAtStarting returns the greatest version of the label that existed at the
// owner's starting position, or -1 if there is none.
func verAtStarting(owner *structs.LabelOwnerState) int64 {
	if len(owner.PreviousVers) == 0 {
		return -1
	}
	return int64(owner.PreviousVers[0])
}

// greatestVersion returns the greatest version of the label known to the
// owner, or nil if no version of the label is known to exist.
func greatestVersion(owner *structs.LabelOwnerState) *uint32 {
	greatest := verAtStarting(owner) + int64(len(owner.UpcomingVers))
	if greatest < 0 {
		return nil
	}
	out := uint32(greatest)
	return &out
}

// ownerTerminal returns the `terminal` value that an owned label is stored
// with, for the purpose of determining when it is stale. This is one past the
// owner's starting position, so that the label becomes stale once a
// distinguished log entry to the right of the starting position is known. If
// the owner hasn't verified any distinguished log entries yet, it is zero so
// that the label is always considered stale.
func ownerTerminal(owner *structs.LabelOwnerState) uint64 {
	if owner.Starting == nil {
		return 0
	}
	return *owner.Starting + 1
}

// labelTerminal returns the `terminal` value that a label is stored with, for
// the purpose of determining when it is stale. A label is stale once the
// client knows of a distinguished log entry at or to the right of `terminal`.
// For contact monitoring state, this is the leftmost position in the
// monitoring map; for owner state, it is given by ownerTerminal. If the label
// has both, the lesser of the two is used.
func labelTerminal(state *structs.ClientLabelState) uint64 {
	terminal := ^uint64(0)
	if state.Owner != nil {
		terminal = ownerTerminal(state.Owner)
	}
	for _, entry := range state.Contact {
		terminal = min(terminal, entry.Position)
	}
	return terminal
}

// verifyUpdateValue checks that, if Third-Party Management is used, that the
// signature from the Service Operator is valid.
func verifyUpdateValue(
	config *structs.PublicConfig,
	label []byte,
	ver uint32,
	val structs.UpdateValue,
) error {
	if config.Mode != structs.ThirdPartyManagement {
		if val.Signature != nil {
			return errors.New("leaf signature provided when not expected")
		}
		return nil
	}

	tbs, err := structs.Marshal(&structs.UpdateTBS{
		Config:  config,
		Label:   label,
		Version: ver,
		Value:   val.Value,
	})
	if err != nil {
		return err
	}

	ok := config.LeafPublicKey.Verify(tbs, val.Signature)
	if !ok {
		return errors.New("leaf signature verification failed")
	}
	return nil
}

func computeCommitment(
	config *structs.PublicConfig,
	opening []byte,
	label []byte,
	ver uint32,
	val structs.UpdateValue,
) ([]byte, error) {
	commitmentValue, err := structs.Marshal(&structs.CommitmentValue{
		Label:   label,
		Version: ver,
		Update:  val,
	})
	if err != nil {
		return nil, err
	}
	return commitments.Commit(config.Suite, opening, commitmentValue), nil
}

// simplifyMonitoringMap removes any redundant entries from the map `ptrs`.
func simplifyMonitoringMap(ptrs map[uint64]uint32, n uint64) {
	for {
		modified := false

		for pos, ver := range ptrs {
			path := math.RightDirectPath(pos, n)
			if len(path) == 0 {
				continue
			} else if parent, ok := ptrs[path[0]]; !ok || parent < ver {
				continue
			}
			delete(ptrs, pos)
			modified = true
		}

		if !modified {
			return
		}
	}
}

// updateContactState is used specifically after Search operations. It adds the
// terminal log entry `x` of the search for version `ver` to the contact
// monitoring map, and removes any map entries that no longer need to be
// monitored as a result of this search.
func updateContactState( // TODO: Can we replace this with ContactState.Set?
	state *structs.ClientLabelState,
	x, n uint64,
	ver uint32,
) error {
	ptrs := make(map[uint64]uint32, len(state.Contact))
	for _, entry := range state.Contact {
		if _, ok := ptrs[entry.Position]; ok {
			return errors.New("contact monitoring state has duplicate position")
		}
		ptrs[entry.Position] = entry.Version
	}

	path := append([]uint64{x}, math.RightDirectPath(x, n)...)
	for _, pos := range path {
		posVer, ok := ptrs[pos]
		if ok && posVer > ver {
			break
		}
		ptrs[pos] = ver
	}
	simplifyMonitoringMap(ptrs, n)

	entries := make([]structs.MonitorMapEntry, 0, len(ptrs))
	for pos, ver := range ptrs {
		entries = append(entries, structs.MonitorMapEntry{Position: pos, Version: ver})
	}
	slices.SortFunc(entries, func(a, b structs.MonitorMapEntry) int {
		return cmp.Compare(a.Position, b.Position)
	})
	state.Contact = entries
	return nil
}

// updateRetainedVersions recomputes the set of VRF outputs and commitments that
// the client should retain.
func updateRetainedVersions(
	state *structs.ClientLabelState,
	handle *algorithms.ReceivedProofHandle,
) error {
	// Calculate the set of versions we need to retain: 1.) versions in a
	// monitoring binary ladder for any version being contact monitored, and 2.)
	// versions in a search binary ladder for any version that's at or to the
	// right of `Starting` (or just 0 if there are none).
	required := make(map[uint32]struct{})

	for _, entry := range state.Contact {
		for _, ver := range math.MonitoringBinaryLadder(entry.Version) {
			required[ver] = struct{}{}
		}
	}

	if state.Owner != nil {
		ownedVersions := make([]uint32, 0)
		next := uint32(0)
		if starting := verAtStarting(state.Owner); starting >= 0 {
			ownedVersions = append(ownedVersions, uint32(starting))
			next = uint32(starting) + 1
		}
		for i := range len(state.Owner.UpcomingVers) {
			ownedVersions = append(ownedVersions, next+uint32(i))
		}

		for _, ver := range allLadderVersions(ownedVersions) {
			required[ver] = struct{}{}
		}
	}

	// Build the slice of RetainedVersion structures that will be stored.
	retained := make([]structs.RetainedVersion, 0, len(required))
	for ver := range required {
		entry, ok := handle.GetVersion(ver) // TODO: Is this necessary?
		if !ok {
			return errors.New("required version not found")
		}
		retained = append(retained, structs.RetainedVersion{
			Version:    ver,
			VrfOutput:  entry.VrfOutput,
			Commitment: entry.Commitment,
		})
	}
	state.Versions = retained

	return nil
}

package transparency

import (
	"bytes"
	"errors"

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

	n  uint64
	nP *uint64
	m  *uint64
}

func newVerifier(
	config *structs.PublicConfig,
	state *structs.ClientState,
	last *uint64,
	fth structs.FullTreeHead,
	proof structs.CombinedTreeProof,
) (*verifier, error) {
	// Set up ProofHandle and DataProvider.
	handle := algorithms.NewReceivedProofHandle(config.Suite, proof)
	provider := algorithms.NewDataProvider(config.Suite, handle)
	if state != nil {
		err := provider.AddRetained(state.FullSubtrees, state.LogEntries)
		if err != nil {
			return nil, err
		}
	}

	// Determine tree sizes.
	var n uint64
	if fth.TreeHead != nil {
		n = fth.TreeHead.TreeSize
	} else if last != nil {
		n = *last
	} else {
		return nil, errors.New("no tree head was provided when required")
	}

	var nP *uint64
	if fth.AuditorTreeHead != nil {
		nP = &fth.AuditorTreeHead.TreeSize
	}

	return &verifier{config, state, fth, handle, provider, n, nP, last}, nil
}

func (v *verifier) updateView() error {
	return algorithms.UpdateView(v.config, v.n, v.m, v.provider)
}

func (v *verifier) greatestVersionSearch(ver uint32) (uint64, error) {
	return algorithms.GreatestVersionSearch(v.config, ver, v.n, v.provider)
}

func (v *verifier) fixedVersionSearch(ver uint32) (uint64, error) {
	return algorithms.FixedVersionSearch(v.config, ver, v.n, v.provider)
}

func (v *verifier) monitor() (*algorithms.Monitor, error) {
	return algorithms.NewMonitor(v.config, v.n, v.provider)
}

func (v *verifier) rightmostDistinguished() (*uint64, error) {
	return algorithms.RightmostDistinguished(v.config, v.n, v.provider)
}

// addLabelState adds all of the retained VRF outputs and commitments to the
// ProofHandle so that they can be used in proof verification. It also ensures,
// if other VRF outputs / commitments were provided in the query response, that
// those are consistent with what we've retained.
func (v *verifier) addLabelState(state *structs.ClientLabelState) error {
	for _, entry := range state.Versions {
		err := v.handle.AddVersion(entry.Version, entry.VrfOutput, entry.Commitment)
		if err != nil {
			return err
		}
	}
	return nil
}

// processLadder converts all of the VRF proofs in `ladder` into VRF outputs and
// adds them to the ProofHandle. Any manually-computed commitments that should
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

func (v *verifier) verifyTreeHead(root, rootP []byte) error {
	if v.fth.TreeHead == nil {
		if v.state == nil {
			return errors.New("same tree head not allowed when client has no state")
		}
		// Note: Verifying that the rightmost timestamp is within the bounds set
		// by MaxAhead and MaxBehind is done in algorithms.UpdateView().
		return nil
	}

	// Verify the size and signature on the tree head.
	if v.state != nil && v.state.TreeHead.TreeSize <= v.n {
		return errors.New("provided tree size is not greater than advertised")
	}
	tbs, err := structs.Marshal(&structs.TreeHeadTBS{
		Config:   v.config,
		TreeSize: v.n,
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
	rightmost, err := v.provider.GetTimestamp(v.n - 1)
	if err != nil {
		return err
	}
	auditorTreeHead := v.fth.AuditorTreeHead
	if auditorTreeHead.Timestamp > rightmost {
		return errors.New("auditor timestamp is greater than rightmost log entry timestamp")
	} else if rightmost-auditorTreeHead.Timestamp > v.config.MaxAuditorLag {
		return errors.New("auditor timestamp is too far behind rightmost log entry timestamp")
	} else if auditorTreeHead.TreeSize > v.n {
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
	result, err := v.provider.Finish(v.n, v.nP, v.m)
	if err != nil {
		return nil, err
	}

	// Compute a candidate root value for the tree and, if needed, the subtree
	// signed by the auditor.
	root, err := log.Root(v.config.Suite, v.n, result.FullSubtrees)
	if err != nil {
		return nil, err
	}

	var rootP []byte
	if v.nP != nil {
		rootP, err = log.Root(v.config.Suite, *v.nP, result.Additional)
		if err != nil {
			return nil, err
		}
	}

	// Verify the signature on the tree head.
	err = v.verifyTreeHead(root, rootP)
	if err != nil {
		return nil, err
	}

	// Compute and return the updated client state.
	updated := &structs.ClientState{
		TreeHead:        v.state.TreeHead,
		AuditorTreeHead: v.fth.AuditorTreeHead,
		FullSubtrees:    result.FullSubtrees,
		LogEntries:      result.LogEntries,
	}
	if v.fth.TreeHead != nil {
		updated.TreeHead = *v.fth.TreeHead
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

func greatestVersion(owner *structs.LabelOwnerState) *uint32 {
	greatest := owner.VerAtStarting + len(owner.UpcomingVers)
	if greatest >= 0 {
		greatest := uint32(greatest)
		return &greatest
	}
	return nil
}

func parseLabelState(config *structs.PublicConfig, raw []byte) (*structs.ClientLabelState, error) {
	if raw == nil {
		return &structs.ClientLabelState{}, nil
	}

	buf := bytes.NewBuffer(raw)
	state, err := structs.NewClientLabelState(config.Suite, buf)
	if err != nil {
		return nil, err
	} else if buf.Len() != 0 {
		return nil, errors.New("unexpected data appended to client label state")
	}

	return state, nil
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

// updateContactState is used specifically after Search operations. It computes
// the rightmost terminal log entry for the search, and removes any map entries
// that no longer need to be monitored as a result of this search.
func updateContactState(
	state *structs.ClientLabelState,
	x, n uint64,
	ver uint32,
) (uint64, error) {
	contact := algorithms.NewContactState(state.Contact)

	path := append([]uint64{x}, math.RightDirectPath(x, n)...)
	for _, pos := range path {
		posVer, ok := contact.Ptrs[pos]
		if ok && posVer > ver {
			break
		}
		contact.Ptrs[pos] = ver
		x = pos
	}
	simplifyMonitoringMap(contact.Ptrs, n)

	state.Contact = contact.Struct()
	return x, nil
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
		starting := state.Owner.VerAtStarting
		ownedVersions := make([]uint32, 0)
		if starting >= 0 {
			ownedVersions = append(ownedVersions, uint32(starting))
		}
		for i := range len(state.Owner.UpcomingVers) {
			ownedVersions = append(ownedVersions, uint32(starting+i+1))
		}

		for _, ver := range allLadderVersions(ownedVersions) {
			required[ver] = struct{}{}
		}
	}

	// Build the slice of RetainedVersion structures that will be stored.
	retained := make([]structs.RetainedVersion, 0, len(required))
	for ver, _ := range required {
		entry, ok := handle.GetVersion(ver)
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

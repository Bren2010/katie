// Package transparency implements the Combined Tree of a Transparency Log.
package transparency

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Bren2010/katie/db"
	"github.com/Bren2010/katie/tree/transparency/algorithms"
	"github.com/Bren2010/katie/tree/transparency/math"
	"github.com/Bren2010/katie/tree/transparency/structs"
	"github.com/Bren2010/katie/tree/transparency/wire"
)

// LabelUpdate is a request to add new versions of a label to the tree, given as
// input to Tree.Mutate.
type LabelUpdate struct {
	Label []byte

	// StartingVersion is the version that must be assigned to the first element
	// of `Values`. It may only be set in Third-Party Management mode, and has
	// the same semantics as UpdateRequest.StartingVersion. If nil, version
	// counters are assigned automatically.
	StartingVersion *uint32

	// Values contains the values for the new label versions, in the order that
	// version counters should be assigned.
	Values []structs.UpdateValue
}

// UpdateRequest represents a request create some new versions of a label. When
// a Transparency Tree is created, it takes as configuration a channel for
// sending UpdateRequest structures to be applied to the tree, so that these
// requests can be received and applied by a central goroutine.
//
// This goroutine must ensure that only one UpdateRequest per `Label` is
// processed in a single log entry. Processing multiple UpdateRequests with the
// same `Label` will cause monitoring failures.
type UpdateRequest struct {
	Label []byte

	// StartingVersion is the version that should be assigned to the first
	// element of `Values`, if any. This is used in Third-Party Management mode
	// to align version counters assigned by the Service Operator and the
	// Manager. If this is greater than what would be assigned naturally, dummy
	// versions need to be sequenced such that they match. If this is less than
	// what would be assigned, an error condition has occured and the request
	// should be rejected.
	StartingVersion *uint32

	// Values contains the values for the new label versions, in the order that
	// version counters should be assigned.
	Values []structs.UpdateValue

	// Response is where the result of processing the request is sent. This
	// channel should have a buffer size of 1 to prevent blocking writes.
	Response chan<- UpdateResponse
}

// UpdateResponse contains the Transparency Log's response to an UpdateRequest.
type UpdateResponse struct {
	// Pos contains the position of the log entry where the new versions of the
	// label were inserted, if successful.
	Pos uint64
	// Err contains any error encountered while processing. If Err is non-nil,
	// then the new versions of the label were not created.
	Err error
}

// Tree is an implementation of a Transparency Tree that handles all state
// management, the evaluation of a VRF, and generating/opening commitments.
type Tree struct {
	config      structs.PrivateConfig
	tx          db.TransparencyStore
	updater     chan<- UpdateRequest
	treeHead    *structs.TreeHead
	auditorHead *structs.AuditorTreeHead

	// commitErr is set if committing to the database failed. The commit may
	// or may not have been persisted, so the in-memory state of the Tree can
	// no longer be trusted and all further writes are refused. A new Tree must
	// be created to reload the state from the database.
	commitErr error

	now func() time.Time // Returns the current time. Overridden in tests.
}

var (
	_ wire.Interface        = &Tree{}
	_ wire.ManagerInterface = &Tree{}
)

func NewTree(
	config structs.PrivateConfig,
	tx db.TransparencyStore,
	updater chan<- UpdateRequest,
) (*Tree, error) {
	rawTreeHead, rawAuditor, err := tx.GetTreeHead()
	if err != nil {
		return nil, err
	}

	var (
		treeHead    *structs.TreeHead
		auditorHead *structs.AuditorTreeHead
	)
	if rawTreeHead != nil {
		treeHead, err = structs.Unmarshal(rawTreeHead, structs.NewTreeHead)
		if err != nil {
			return nil, err
		}
	}
	if config.Mode == structs.ThirdPartyAuditing && rawAuditor != nil {
		auditorHead, err = structs.Unmarshal(rawAuditor, structs.NewAuditorTreeHead)
		if err != nil {
			return nil, err
		}
	}

	return &Tree{
		config:      config,
		tx:          tx,
		updater:     updater,
		treeHead:    treeHead,
		auditorHead: auditorHead,

		now: time.Now,
	}, nil
}

// TreeHead returns the most recently issued tree head, or nil if the tree is
// empty and no tree head has been issued yet.
func (t *Tree) TreeHead() *structs.TreeHead { return t.treeHead }

func (t *Tree) n() uint64 {
	if t.treeHead != nil {
		return t.treeHead.TreeSize
	}
	return 0
}

func nP(fth *structs.FullTreeHead) *uint64 {
	if fth.AuditorTreeHead != nil {
		return &fth.AuditorTreeHead.TreeSize
	}
	return nil
}

// checkWritable returns an error if the Tree is not allowed to write to the
// database because a previous commit failed.
func (t *Tree) checkWritable() error {
	if t.commitErr != nil {
		return fmt.Errorf("refusing to write after failed commit, tree must be reloaded: %w", t.commitErr)
	}
	return nil
}

// commit commits all buffered changes to the database. If this fails, the Tree
// refuses all further writes.
func (t *Tree) commit() error {
	if err := t.tx.Commit(); err != nil {
		t.commitErr = err
		return err
	}
	return nil
}

func (t *Tree) fullTreeHead(last *uint64) (*structs.FullTreeHead, error) {
	if t.treeHead == nil {
		return nil, errors.New("can not operate on an empty tree")
	} else if last != nil {
		if *last == t.n() {
			return &structs.FullTreeHead{}, nil
		} else if *last > t.n() {
			return nil, errors.New("tree size advertised by user is greater than current tree size")
		}
	} else if t.config.Mode == structs.ThirdPartyAuditing && t.auditorHead == nil {
		return nil, errors.New("can not provide tree head before an auditor tree head has been set")
	}
	return &structs.FullTreeHead{TreeHead: t.treeHead, AuditorTreeHead: t.auditorHead}, nil
}

func (t *Tree) updateView(last *uint64, provider *algorithms.DataProvider) error {
	if last != nil { // Load the log entries retained by the user.
		frontier := math.Frontier(*last)

		results, err := t.tx.BatchGet(frontier)
		if err != nil {
			return err
		}

		logEntries := make(map[uint64]structs.LogEntry)
		for i, pos := range frontier {
			if results[i] == nil {
				return errors.New("expected frontier log entry not found")
			}
			entry, err := structs.UnmarshalWith(results[i], structs.NewLogEntry, t.config.Suite)
			if err != nil {
				return err
			}
			logEntries[pos] = *entry
		}

		// Add the parsed frontier log entries as retained state. The retained
		// full subtrees don't need to be added since they'll never be needed by
		// the DataProvider.
		provider.AddRetained(nil, logEntries)
	}

	return algorithms.UpdateView(t.config.Public(), t.n(), last, provider)
}

// Search looks up a requested version of a label. It returns the corresponding
// value and a proof that the search was executed correctly.
//
// If `req.Version` is nil, a greatest-version search is performed for the most
// recent version of the label. Otherwise, a fixed-version search is performed
// for the indicated version.
func (t *Tree) Search(
	ctx context.Context,
	req *structs.SearchRequest,
) (*structs.SearchResponse, error) {
	fth, err := t.fullTreeHead(req.Last)
	if err != nil {
		return nil, err
	}

	// Load label index and determine the greatest version that exists, if any.
	index, err := t.getIndex(req.Label)
	if err != nil {
		return nil, err
	}
	greatest := int64(len(index)) - 1

	// Determine the target version for our search / verify that the version
	// requested by the user is acceptable and exists.
	var target uint32
	if req.Version == nil {
		if greatest < 0 {
			return nil, algorithms.ErrLabelNotFound
		}
		target = uint32(greatest)
	} else if int64(*req.Version) > greatest {
		return nil, algorithms.ErrLabelNotFound
	} else {
		target = *req.Version
	}
	openingAndValue, err := t.getVersion(req.Label, target)
	if err != nil {
		return nil, err
	}

	// Execute the algorithm to update the user's view of the tree, and then
	// either a greatest-version or fixed-version search.
	handle := algorithms.NewProducedProofHandle(t.config.Suite, t.tx, index)
	provider := algorithms.NewDataProvider(t.config.Suite, handle)
	if err := t.updateView(req.Last, provider); err != nil {
		return nil, err
	}
	if req.Version == nil {
		_, err = algorithms.GreatestVersionSearch(t.config.Public(), target, t.n(), provider)
	} else {
		_, err = algorithms.FixedVersionSearch(t.config.Public(), target, t.n(), provider)
	}
	if err != nil {
		return nil, err
	}

	// Compute the VRF output and proof for each version in the binary ladder.
	// A commitment is provided for every version that exists, other than the
	// target version, which the user computes themselves.
	ladder := math.SearchBinaryLadder(target, target, nil, nil)
	steps, vrfOutputs, err := t.getBinaryLadder(req.Label, ladder, greatest, t.n()-1)
	if err != nil {
		return nil, err
	}
	if err := t.addRequiredVersions(handle, req.Label, vrfOutputs); err != nil {
		return nil, err
	}
	for i, ver := range ladder {
		if ver == target {
			steps[i].Commitment = nil
		}
	}

	// Assemble response.
	var version *uint32
	if req.Version == nil {
		version = &target
	}
	combinedProof, err := provider.Output(t.n(), nP(fth), req.Last)
	if err != nil {
		return nil, err
	}
	return &structs.SearchResponse{
		FullTreeHead: *fth,

		Version: version,
		Opening: openingAndValue.Opening,
		Value:   openingAndValue.Value,

		BinaryLadder: steps,
		Search:       *combinedProof,
	}, nil
}

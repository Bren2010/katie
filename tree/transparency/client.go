package transparency

import (
	"errors"

	"github.com/Bren2010/katie/db"
	"github.com/Bren2010/katie/tree/log"
	"github.com/Bren2010/katie/tree/transparency/algorithms"
	"github.com/Bren2010/katie/tree/transparency/math"
	"github.com/Bren2010/katie/tree/transparency/structs"
)

type verifier struct {
	config *structs.PublicConfig
	state  *structs.ClientState

	handle   *algorithms.ReceivedProofHandle
	provider *algorithms.DataProvider

	n  uint64
	nP *uint64
	m  *uint64
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

func (v *verifier) finish(fth structs.FullTreeHead) (*structs.ClientState, error) {
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
	rightmost, err := v.provider.GetTimestamp(v.n - 1)
	if err != nil {
		return nil, err
	}

	err = verifyTreeHead(v.config, v.state, fth, root, rootP, rightmost)
	if err != nil {
		return nil, err
	}

	// Compute and return the updated client state.
	updated := &structs.ClientState{
		TreeHead:        v.state.TreeHead,
		AuditorTreeHead: fth.AuditorTreeHead,
		FullSubtrees:    result.FullSubtrees,
		LogEntries:      result.LogEntries,
	}
	if fth.TreeHead != nil {
		updated.TreeHead = *fth.TreeHead
	}
	return updated, nil
}

// VerifyFunc is a function returned by one of the methods on Client, used for
// verifying a response to a specific request. The function is tied to the
// specific request that it was returned with and can not be reused.
type VerifyFunc[T any] func(res T) error

// Client implements request generation and response verification for a Key
// Transparency client.
type Client struct {
	config *structs.PublicConfig
	tx     db.ClientStore
}

func NewClient(config *structs.PublicConfig, tx db.ClientStore) (*Client, error) {
	ok := false
	switch config.Mode {
	case structs.ContactMonitoring:
		ok = config.LeafPublicKey == nil && config.AuditorPublicKey == nil
	case structs.ThirdPartyManagement:
		ok = config.LeafPublicKey != nil && config.AuditorPublicKey == nil
	case structs.ThirdPartyAuditing:
		ok = config.LeafPublicKey == nil && config.AuditorPublicKey != nil
	}
	if config.MaximumLifetime > 0 && config.MaximumLifetime <= config.ReasonableMonitoringWindow {
		ok = false
	}
	if !ok {
		return nil, errors.New("invalid configuration given")
	}

	return &Client{
		config: config,
		tx:     tx,
	}, nil
}

func (c *Client) start(
	last *uint64,
	fth structs.FullTreeHead,
	proof structs.CombinedTreeProof,
) (*verifier, error) {
	// Load client state and check that it matches the request.
	state, err := c.getState()
	if err != nil {
		return nil, err
	}
	stateMatches := (state == nil && last == nil) ||
		(state != nil && last != nil && state.TreeHead.TreeSize == *last)
	if !stateMatches {
		return nil, errors.New("client state does not match request")
	}

	// Set up ProofHandle and DataProvider.
	handle := algorithms.NewReceivedProofHandle(c.config.Suite, proof)
	provider := algorithms.NewDataProvider(c.config.Suite, handle)
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

	return &verifier{c.config, state, handle, provider, n, nP, last}, nil
}

// GreatestVersionSearch returns a SearchRequest for the greatest version of
// `label` and a function to verify the corresponding SearchResponse.
func (c *Client) GreatestVersionSearch(label []byte) (
	*structs.SearchRequest,
	VerifyFunc[*structs.SearchResponse],
	error,
) {
	last, err := c.last()
	if err != nil {
		return nil, nil, err
	}
	req := &structs.SearchRequest{Last: last, Label: label, Version: nil}
	return req, c.search(req), nil
}

// FixedVersionSearch returns a SearchRequest for the requested version of
// `label` and a function to verify the corresponding SearchResponse.
func (c *Client) FixedVersionSearch(label []byte, ver uint32) (
	*structs.SearchRequest,
	VerifyFunc[*structs.SearchResponse],
	error,
) {
	last, err := c.last()
	if err != nil {
		return nil, nil, err
	}
	req := &structs.SearchRequest{Last: last, Label: label, Version: &ver}
	return req, c.search(req), nil
}

func (c *Client) search(req *structs.SearchRequest) VerifyFunc[*structs.SearchResponse] {
	return func(res *structs.SearchResponse) error {
		v, err := c.start(req.Last, res.FullTreeHead, res.Search)
		if err != nil {
			return err
		}

		// Determine the target version for the search.
		var target uint32
		if req.Version != nil {
			target = *req.Version
		} else if res.Version != nil {
			target = *res.Version
		} else {
			// This will never happen if the SearchResponse was properly
			// decoded, but it might not have been.
			return errors.New("unexpected error occurred")
		}

		// If a Third-Party Manager is being used, verify `value`.
		err = c.verifyUpdateValue(req.Label, target, res.Value)
		if err != nil {
			return err
		}

		// Verify that the expected number of entries is present in
		// `binary_ladder` and compute the VRF output for each version.
		ladder := math.SearchBinaryLadder(target, target, nil, nil)
		commitment, err := c.computeCommitment(res.Opening, req.Label, target, res.Value)
		if err != nil {
			return err
		}
		err = c.processLadder(v.handle, req.Label, res.BinaryLadder, ladder, map[uint32][]byte{
			target: commitment,
		})
		if err != nil {
			return err
		}

		// Verify the proof.
		if err := v.updateView(); err != nil {
			return err
		}
		var terminal uint64
		if req.Version == nil {
			terminal, err = v.greatestVersionSearch(target)
		} else {
			terminal, err = v.fixedVersionSearch(target)
		}
		if err != nil {
			return err
		}
		updated, err := v.finish(res.FullTreeHead)
		if err != nil {
			return err
		}

		// Try to bail out early by updating only global state, but also update
		// label-specific state if necessary.
		if c.config.Mode != structs.ContactMonitoring {
			return c.putState(updated)
		}
		rightmostDLE, err := v.rightmostDistinguished()
		if err != nil {
			return err
		} else if rightmostDLE != nil && terminal <= *rightmostDLE {
			return c.putState(updated)
		}

		labelState, err := c.getLabelState(req.Label)
		if err != nil {
			return err
		}
		// TODO: Update label state.
		return c.putLabelState()
	}
}

func (c *Client) OwnerInit(label []byte) (
	*structs.OwnerInitRequest,
	VerifyFunc[*structs.OwnerInitResponse],
	error,
) {
	panic("not implemented")
}

// NextOwnerMonitor returns the next label where Owner Monitoring is
// recommended, or nil if none.
func (c *Client) NextOwnerMonitor() ([]byte, error) {
	panic("not implemented")
}

func (c *Client) OwnerMonitor(label []byte) (
	*structs.OwnerMonitorRequest,
	VerifyFunc[*structs.OwnerMonitorResponse],
	error,
) {
	panic("not implemented")
}

// NextContactMonitor returns the next label where Contact Monitoring is
// recommended, or nil if none.
func (c *Client) NextContactMonitor() ([]byte, error) {
	panic("not implemented")
}

func (c *Client) ContactMonitor(label []byte) (
	*structs.ContactMonitorRequest,
	VerifyFunc[*structs.ContactMonitorRequest],
	error,
) {
	panic("not implemented")
}

func (c *Client) Update(label []byte, values [][]byte) (
	*structs.UpdateRequest,
	VerifyFunc[*structs.UpdateResponse],
	error,
) {
	panic("not implemented")
}

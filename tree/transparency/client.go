package transparency

import (
	"bytes"
	"errors"

	"github.com/Bren2010/katie/crypto/commitments"
	"github.com/Bren2010/katie/db"
	"github.com/Bren2010/katie/tree/transparency/algorithms"
	"github.com/Bren2010/katie/tree/transparency/math"
	"github.com/Bren2010/katie/tree/transparency/structs"
)

func getTreeSizes(last *uint64, fth structs.FullTreeHead) (uint64, *uint64, *uint64, error) {
	var n uint64
	if fth.TreeHead != nil {
		n = fth.TreeHead.TreeSize
	} else if last != nil {
		n = *last
	} else {
		return 0, nil, nil, errors.New("no tree head was provided when required")
	}

	var nP *uint64
	if fth.AuditorTreeHead != nil {
		nP = &fth.AuditorTreeHead.TreeSize
	}

	return n, nP, last, nil
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

func (c *Client) getState() (*structs.ClientState, error) {
	raw, err := c.tx.GetTreeHead()
	if err != nil {
		return nil, err
	} else if raw == nil {
		return nil, nil
	}

	buf := bytes.NewBuffer(raw)
	state, err := structs.NewClientState(c.config.Suite, buf)
	if err != nil {
		return nil, err
	} else if buf.Len() != 0 {
		return nil, errors.New("unexpected data appended to client state")
	}

	return state, nil
}

func (c *Client) last() (*uint64, error) {
	state, err := c.getState()
	if err != nil {
		return nil, err
	} else if state == nil {
		return nil, nil
	}
	return &state.TreeHead.TreeSize, nil
}

func (c *Client) verifyTreeHead(
	state *structs.ClientState,
	fth structs.FullTreeHead,
	root, rootP []byte,
	rightmost uint64,
) error {
	if fth.TreeHead == nil {
		if state == nil {
			return errors.New("same tree head not allowed when client has no state")
		}
		// Note: Verifying that the rightmost timestamp is within the bounds set by
		// MaxAhead and MaxBehind is done in algorithms.UpdateView().
		return nil
	}

	// Verify the size and signature on the tree head.
	if state != nil && state.TreeHead.TreeSize <= fth.TreeHead.TreeSize {
		return errors.New("provided tree size is not greater than advertised")
	}
	tbs, err := structs.Marshal(&structs.TreeHeadTBS{
		Config:   c.config,
		TreeSize: fth.TreeHead.TreeSize,
		Root:     root,
	})
	if err != nil {
		return err
	}
	ok := c.config.SignatureKey.Verify(tbs, fth.TreeHead.Signature)
	if !ok {
		return errors.New("failed to verify tree head signature")
	} else if fth.AuditorTreeHead == nil {
		return nil
	}

	// Verify size and signature of the auditor tree head.
	if state != nil {
		if state.AuditorTreeHead == nil {
			return errors.New("missing previous auditor tree head")
		} else if state.AuditorTreeHead.TreeSize < c.config.AuditorStartPos {
			return errors.New("previous auditor tree size does not cover new auditor start position")
		}
	}
	if fth.AuditorTreeHead.Timestamp > rightmost {
		return errors.New("auditor timestamp is greater than rightmost log entry timestamp")
	} else if rightmost-fth.AuditorTreeHead.Timestamp > c.config.MaxAuditorLag {
		return errors.New("auditor timestamp is too far behind rightmost log entry timestamp")
	} else if fth.AuditorTreeHead.TreeSize > fth.TreeHead.TreeSize {
		return errors.New("auditor tree size is greater than transparency log tree size")
	}

	tbs, err = structs.Marshal(&structs.AuditorTreeHeadTBS{
		Config:    c.config,
		Timestamp: fth.AuditorTreeHead.Timestamp,
		TreeSize:  fth.AuditorTreeHead.TreeSize,
		Root:      rootP,
	})
	if err != nil {
		return err
	}
	ok = c.config.AuditorPublicKey.Verify(tbs, fth.TreeHead.Signature)
	if !ok {
		return errors.New("failed to verify auditor signature")
	}

	return nil
}

func (c *Client) verifyUpdateValue(label []byte, ver uint32, val structs.UpdateValue) error {
	if c.config.Mode != structs.ThirdPartyManagement {
		if val.Signature != nil {
			return errors.New("leaf signature provided when not expected")
		}
		return nil
	}

	tbs, err := structs.Marshal(&structs.UpdateTBS{
		Config:  c.config,
		Label:   label,
		Version: ver,
		Value:   val.Value,
	})
	if err != nil {
		return err
	}

	ok := c.config.LeafPublicKey.Verify(tbs, val.Signature)
	if !ok {
		return errors.New("leaf signature verification failed")
	}
	return nil
}

func (c *Client) processLadder(
	handle *algorithms.ReceivedProofHandle,
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
		vrfOutput, err := c.config.VrfKey.Verify(input, ladder[i].Proof)
		if err != nil {
			return err
		}

		commitment, ok := manual[ver]
		if ok && ladder[i].Commitment != nil {
			return errors.New("commitment provided when not expected")
		} else if !ok {
			commitment = ladder[i].Commitment
		}

		if err := handle.AddVersion(ver, vrfOutput, commitment); err != nil {
			return err
		}
	}

	return nil
}

func (c *Client) computeCommitment(
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
	return commitments.Commit(c.config.Suite, opening, commitmentValue), nil
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
		// Load client state and check that it matches the request.
		state, err := c.getState()
		if err != nil {
			return err
		}
		stateMatches := (state == nil && req.Last == nil) ||
			(state != nil && req.Last != nil && state.TreeHead.TreeSize == *req.Last)
		if !stateMatches {
			return errors.New("client state does not match request")
		}

		// Set up ProofHandle and DataProvider.
		handle := algorithms.NewReceivedProofHandle(c.config.Suite, res.Search)
		provider := algorithms.NewDataProvider(c.config.Suite, handle)
		if state != nil {
			err := provider.AddRetained(state.FullSubtrees, state.LogEntries)
			if err != nil {
				return err
			}
		}

		// Determine tree size.
		n, nP, m, err := getTreeSizes(req.Last, res.FullTreeHead)
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
		err = c.processLadder(handle, req.Label, res.BinaryLadder, ladder, map[uint32][]byte{
			target: commitment,
		})
		if err != nil {
			return err
		}

		// Verify the proof.
		if err := algorithms.UpdateView(c.config, n, m, provider); err != nil {
			return err
		}
		var terminal uint64
		if req.Version == nil {
			terminal, err = algorithms.GreatestVersionSearch(c.config, target, n, provider)
		} else {
			terminal, err = algorithms.FixedVersionSearch(c.config, target, n, provider)
		}
		if err != nil {
			return err
		}
		result, err := provider.Finish(n, nP, m)
		if err != nil {
			return err
		}

		// Compute a candidate root value for the tree and verify the tree head.

		return nil
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

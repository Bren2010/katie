package transparency

import (
	"bytes"
	"errors"

	"github.com/Bren2010/katie/db"
	"github.com/Bren2010/katie/tree/transparency/math"
	"github.com/Bren2010/katie/tree/transparency/structs"
)

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
	raw, err := c.tx.GetState()
	if err != nil {
		return nil, err
	} else if raw == nil {
		return nil, nil
	}

	buf := bytes.NewBuffer(raw)
	state, err := structs.NewClientState(c.config, buf)
	if err != nil {
		return nil, err
	} else if buf.Len() != 0 {
		return nil, errors.New("unexpected data appended to client state")
	}

	return state, nil
}

func (c *Client) getLabelState(label []byte) (*structs.ClientLabelState, error) {
	raw, err := c.tx.GetLabelState(label)
	if err != nil {
		return nil, err
	} else if raw == nil {
		return nil, nil
	}

	buf := bytes.NewBuffer(raw)
	state, err := structs.NewClientLabelState(buf)
	if err != nil {
		return nil, err
	} else if buf.Len() != 0 {
		return nil, errors.New("unexpected data appended to client label state")
	}

	return state, nil
}

func (c *Client) putState(updated *structs.ClientState) error {
	raw, err := structs.Marshal(updated)
	if err != nil {
		return err
	}
	return c.tx.PutState(raw)
}

func (c *Client) putLabelState(
	updated *structs.ClientState,
	label []byte,
	updatedLabel *structs.ClientLabelState,
	terminal uint64,
) error {
	raw, err := structs.Marshal(updated)
	if err != nil {
		return err
	}
	var rawLabel []byte
	if len(updatedLabel.Contact) > 0 || updatedLabel.Owner != nil {
		rawLabel, err = structs.Marshal(updatedLabel)
		if err != nil {
			return err
		}
	}
	return c.tx.PutLabelState(raw, label, rawLabel, terminal)
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

func (c *Client) start(
	last *uint64,
	fth structs.FullTreeHead,
	proof structs.CombinedTreeProof,
) (*verifier, error) {
	state, err := c.getState()
	if err != nil {
		return nil, err
	}
	stateMatches := (state == nil && last == nil) ||
		(state != nil && last != nil && state.TreeHead.TreeSize == *last)
	if !stateMatches {
		return nil, errors.New("client state does not match request")
	}
	return newVerifier(c.config, state, last, fth, proof)
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
		err = verifyUpdateValue(c.config, req.Label, target, res.Value)
		if err != nil {
			return err
		}

		// Verify that the expected number of entries is present in
		// `binary_ladder` and compute the VRF output for each version.
		ladder := math.SearchBinaryLadder(target, target, nil, nil)
		commitment, err := computeCommitment(c.config, res.Opening, req.Label, target, res.Value)
		if err != nil {
			return err
		}
		err = v.processLadder(req.Label, res.BinaryLadder, ladder, map[uint32][]byte{
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
		updated, err := v.finish()
		if err != nil {
			return err
		}

		// Try to bail out early by updating only the global state, but also
		// update the label-specific state if it's necessary.
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
		terminal = updateLabelState(labelState, terminal, v.n, target)
		return c.putLabelState(updated, req.Label, labelState, terminal)
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

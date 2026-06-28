package transparency

import (
	"bytes"
	"errors"

	"github.com/Bren2010/katie/db"
	"github.com/Bren2010/katie/tree/transparency/algorithms"
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

func parseLabelState(raw []byte) (*structs.ClientLabelState, error) {
	if raw == nil {
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

func (c *Client) getLabelState(label []byte) (*structs.ClientLabelState, error) {
	raw, err := c.tx.GetLabelState(label)
	if err != nil {
		return nil, err
	}
	return parseLabelState(raw)
}

func (c *Client) getStaleLabel(cutoff uint64) ([]byte, *structs.ClientLabelState, error) {
	label, raw, err := c.tx.GetStaleLabel(cutoff)
	if err != nil {
		return nil, nil, err
	}
	state, err := parseLabelState(raw)
	if err != nil {
		return nil, nil, err
	}
	return label, state, nil
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

func (c *Client) lastAndRightmostDLE() (uint64, uint64, error) {
	state, err := c.getState()
	if err != nil {
		return 0, 0, err
	} else if state == nil {
		return 0, 0, errors.New("unable to make request with no state")
	}
	last := state.TreeHead.TreeSize

	provider := algorithms.NewDataProvider(c.config.Suite, nil)
	provider.AddRetained(nil, state.LogEntries)
	rightmostDLE, err := algorithms.RightmostDistinguished(c.config, last, provider)
	if err != nil {
		return 0, 0, err
	} else if rightmostDLE == nil {
		return 0, 0, errors.New("unable to make request if no distinguished log entries exist")
	}

	return last, *rightmostDLE, nil
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
	labelState, err := c.getLabelState(label)
	if err != nil {
		return nil, nil, err
	} else if labelState != nil && labelState.Owner != nil {
		return nil, nil, errors.New("label is already owned")
	}

	last, start, err := c.lastAndRightmostDLE()
	if err != nil {
		return nil, nil, err
	}
	req := &structs.OwnerInitRequest{Last: &last, Label: label, Start: start}
	return req, c.ownerInit(req), nil
}

func (c *Client) ownerInit(req *structs.OwnerInitRequest) VerifyFunc[*structs.OwnerInitResponse] {
	return func(res *structs.OwnerInitResponse) error {
		v, err := c.start(req.Last, res.FullTreeHead, res.Init)
		if err != nil {
			return err
		}

		// Verify that the expected number of entries is in `BinaryLadder` and
		// that a commitment is provided for each version in `GreatestVersion`.
		ladder := allLadderVersions(res.GreatestVersions)
		err = v.processLadder(req.Label, res.BinaryLadder, ladder, nil)
		if err != nil {
			return err
		}

		greatestVersions := make(map[uint32]struct{})
		for _, ver := range res.GreatestVersions {
			greatestVersions[ver] = struct{}{}
		}
		for i, ver := range ladder {
			if _, ok := greatestVersions[ver]; !ok {
				continue
			} else if res.BinaryLadder[i].Commitment == nil {
				return errors.New("commitment not provided when expected")
			}
		}

		// Verify the proof.
		if err := v.updateView(); err != nil {
			return err
		}
		monitor, err := v.monitor()
		if err != nil {
			return err
		}
		_, err = monitor.OwnerInit(req.Start, res.GreatestVersions)
		if err != nil {
			return err
		}
		updated, err := v.finish()
		if err != nil {
			return err
		}

		// Update the global and label-specific state.
		labelState, err := c.getLabelState(req.Label)
		if err != nil {
			return err
		}
		labelState.Owner = &structs.LabelOwnerState{
			Starting:      monitor.Owner.Starting,
			VerAtStarting: monitor.Owner.VerAtStarting,
			UpcomingVers:  monitor.Owner.UpcomingVers,
		}
		return c.putLabelState(updated, req.Label, labelState, req.Start)
	}
}

func (c *Client) Monitor() (
	structs.Marshaller, // *structs.ContactMonitorRequest or *structs.OwnerMonitorRequest
	VerifyFunc[structs.Marshaller], // *structs.ContactMonitorResponse or *structs.OwnerMonitorResponse
	error,
) {
	last, cutoff, err := c.lastAndRightmostDLE()
	if err != nil {
		return nil, nil, err
	}
	label, labelState, err := c.getStaleLabel(cutoff)
	if err != nil {
		return nil, nil, err
	} else if labelState == nil {
		return nil, nil, errors.New("unexpected error occurred")
	}

	if labelState.Owner == nil {
		req := &structs.ContactMonitorRequest{
			Last:    &last,
			Label:   label,
			Entries: labelState.Contact,
		}
		return req, c.contactMonitor(req), nil
	}
	req := &structs.OwnerMonitorRequest{
		Last:    &last,
		Label:   label,
		Entries: labelState.Contact,
		Start:   labelState.Owner.Starting,
	}
	greatest := labelState.Owner.VerAtStarting + len(labelState.Owner.UpcomingVers)
	if greatest >= 0 {
		greatest := uint32(greatest)
		req.GreatestVersion = &greatest
	}
	return req, c.ownerMonitor(req), nil
}

func (c *Client) contactMonitor(req *structs.ContactMonitorRequest) VerifyFunc[structs.Marshaller] {
	return func(marsh structs.Marshaller) error {
		res, ok := marsh.(*structs.ContactMonitorResponse)
		if !ok {
			return errors.New("expected contact monitor response, unexpected value received")
		}
		labelState, err := c.getLabelState(req.Label)
		if err != nil {
			return err
		}

		// Verify the proof.
		v, err := c.start(req.Last, res.FullTreeHead, res.Monitor)
		if err != nil {
			return err
		} else if err := v.updateView(); err != nil {
			return err
		}
		monitor, err := v.monitor()
		if err != nil {
			return err
		}
		monitor.Contact = &algorithms.ContactState{Ptrs: labelState.GetContact()}
		if err := monitor.ContactMonitor(); err != nil {
			return err
		}
		updated, err := v.finish()
		if err != nil {
			return err
		}

		// Update the global and label-specific state.
		labelState.SetContact(monitor.Contact.Ptrs)

		terminal, err := v.rightmostDistinguished()
		if err != nil {
			return err
		} else if terminal == nil {
			return errors.New("unable to compute rightmost distinguished log entry")
		}

		return c.putLabelState(updated, req.Label, labelState, *terminal)
	}
}

func (c *Client) ownerMonitor(req *structs.OwnerMonitorRequest) VerifyFunc[structs.Marshaller] {
	return func(marsh structs.Marshaller) error {
		res, ok := marsh.(*structs.OwnerMonitorResponse)
		if !ok {
			return errors.New("expected owner monitor response, unexpected value received")
		}
		panic("not implemented")
	}
}

func (c *Client) Update(label []byte, values [][]byte) (
	*structs.UpdateRequest,
	VerifyFunc[*structs.UpdateResponse],
	error,
) {
	panic("not implemented")
}

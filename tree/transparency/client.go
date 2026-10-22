package transparency

import (
	"errors"
	"time"

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
	now    func() time.Time // Returns the current time. Overridden in tests.
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
		now:    time.Now,
	}, nil
}

func (c *Client) getState() (*structs.ClientState, error) {
	raw, err := c.tx.GetState()
	if err != nil {
		return nil, err
	} else if raw == nil {
		return nil, nil
	}
	return structs.UnmarshalWith(raw, structs.NewClientState, c.config)
}

func (c *Client) getLabelState(label []byte) (*structs.ClientLabelState, error) {
	raw, err := c.tx.GetLabelState(label)
	if err != nil {
		return nil, err
	}
	return parseLabelState(c.config, raw)
}

func (c *Client) getStaleLabel(cutoff uint64) ([]byte, *structs.ClientLabelState, error) {
	label, raw, err := c.tx.GetStaleLabel(cutoff)
	if err != nil {
		return nil, nil, err
	} else if label == nil {
		return nil, nil, nil
	}
	state, err := parseLabelState(c.config, raw)
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

// GreatestVersionSearch returns a SearchRequest for the greatest version of
// `label` and a function to verify the corresponding SearchResponse.
func (c *Client) GreatestVersionSearch(label []byte) (
	*structs.SearchRequest,
	VerifyFunc[*structs.SearchResponse],
	error,
) {
	state, err := c.getState()
	if err != nil {
		return nil, nil, err
	}
	req := &structs.SearchRequest{Last: getLast(state), Label: label, Version: nil}
	return req, c.search(state, req), nil
}

// FixedVersionSearch returns a SearchRequest for the requested version of
// `label` and a function to verify the corresponding SearchResponse.
func (c *Client) FixedVersionSearch(label []byte, ver uint32) (
	*structs.SearchRequest,
	VerifyFunc[*structs.SearchResponse],
	error,
) {
	state, err := c.getState()
	if err != nil {
		return nil, nil, err
	}
	req := &structs.SearchRequest{Last: getLast(state), Label: label, Version: &ver}
	return req, c.search(state, req), nil
}

func (c *Client) search(
	state *structs.ClientState,
	req *structs.SearchRequest,
) VerifyFunc[*structs.SearchResponse] {
	return func(res *structs.SearchResponse) error {
		v, err := newVerifier(c.config, state, res.FullTreeHead, c.now(), req.Last, res.Search)
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

		// Try to bail out early by updating only the global state.
		if c.config.Mode != structs.ContactMonitoring {
			return c.putState(updated)
		}
		rightmostDLE, err := v.rightmostDistinguished()
		if err != nil {
			return err
		} else if rightmostDLE != nil && terminal <= *rightmostDLE {
			return c.putState(updated)
		}

		// Updating label-specific state is necessary.
		labelState, err := c.getLabelState(req.Label)
		if err != nil {
			return err
		} else if err := v.addLabelState(labelState); err != nil {
			return err
		}
		if err := updateContactState(labelState, terminal, v.n, target); err != nil {
			return err
		} else if err := updateRetainedVersions(labelState, v.handle); err != nil {
			return err
		}
		return c.putLabelState(updated, req.Label, labelState, labelTerminal(labelState))
	}
}

// OwnerInit returns an OwnerInitRequest for the requested `label` and a
// function to verify the corresponding OwnerInitResponse.
func (c *Client) OwnerInit(label []byte) (
	*structs.OwnerInitRequest,
	VerifyFunc[*structs.OwnerInitResponse],
	error,
) {
	state, err := c.getState()
	if err != nil {
		return nil, nil, err
	}
	labelState, err := c.getLabelState(label)
	if err != nil {
		return nil, nil, err
	} else if labelState != nil && labelState.Owner != nil {
		return nil, nil, errors.New("label is already owned")
	}
	start, err := getDistinguished(c.config, state)
	if err != nil {
		return nil, nil, err
	}

	req := &structs.OwnerInitRequest{Last: getLast(state), Label: label, Start: &start}
	return req, c.ownerInit(state, labelState, req), nil
}

func (c *Client) ownerInit(
	state *structs.ClientState,
	labelState *structs.ClientLabelState,
	req *structs.OwnerInitRequest,
) VerifyFunc[*structs.OwnerInitResponse] {
	return func(res *structs.OwnerInitResponse) error {
		v, err := newVerifier(c.config, state, res.FullTreeHead, c.now(), req.Last, res.Init)
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
			_, ok := greatestVersions[ver]
			if ok && res.BinaryLadder[i].Commitment == nil {
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
		labelState.Owner = monitor.Owner.Struct()
		if err := v.addLabelState(labelState); err != nil {
			return err
		} else if err := updateRetainedVersions(labelState, v.handle); err != nil {
			return err
		}
		return c.putLabelState(updated, req.Label, labelState, labelTerminal(labelState))
	}
}

// Monitor determines a single label where monitoring is recommended and returns
// either a ContactMonitorRequest or an OwnerMonitorRequest, depending on
// whether the label is owned or not. It returns a function to verify the
// corresponding ContactMonitorResponse or OwnerMonitorResponse.
//
// This function may return nil if no label needs to be monitored right now.
func (c *Client) Monitor() (
	structs.Marshaller, // *structs.ContactMonitorRequest or *structs.OwnerMonitorRequest
	VerifyFunc[structs.Marshaller], // *structs.ContactMonitorResponse or *structs.OwnerMonitorResponse
	error,
) {
	state, err := c.getState()
	if err != nil {
		return nil, nil, err
	}
	cutoff, err := getDistinguished(c.config, state)
	if err != nil {
		return nil, nil, err
	}
	label, labelState, err := c.getStaleLabel(cutoff)
	if err != nil {
		return nil, nil, err
	} else if label == nil {
		return nil, nil, nil
	} else if len(labelState.Contact) == 0 && labelState.Owner == nil {
		return nil, nil, errors.New("unexpected error occurred")
	}

	if labelState.Owner == nil {
		req := &structs.ContactMonitorRequest{
			Last: getLast(state),

			Label:   label,
			Entries: labelState.Contact,
		}
		return req, c.contactMonitor(state, labelState, req), nil
	}
	req := &structs.OwnerMonitorRequest{
		Last: getLast(state),

		Label:           label,
		Entries:         labelState.Contact,
		Start:           labelState.Owner.Starting,
		GreatestVersion: greatestVersion(labelState.Owner),
	}
	return req, c.ownerMonitor(state, labelState, req), nil
}

func (c *Client) contactMonitor(
	state *structs.ClientState,
	labelState *structs.ClientLabelState,
	req *structs.ContactMonitorRequest,
) VerifyFunc[structs.Marshaller] {
	return func(marsh structs.Marshaller) error {
		res, ok := marsh.(*structs.ContactMonitorResponse)
		if !ok {
			return errors.New("expected contact monitor response, unexpected value received")
		}

		// Verify the proof.
		v, err := newVerifier(c.config, state, res.FullTreeHead, c.now(), req.Last, res.Monitor)
		if err != nil {
			return err
		} else if err := v.addLabelState(labelState); err != nil {
			return err
		} else if err := v.updateView(); err != nil {
			return err
		}
		monitor, err := v.monitor()
		if err != nil {
			return err
		}
		if err := monitor.SetContactState(labelState.Contact); err != nil {
			return err
		}
		if err := monitor.ContactMonitor(); err != nil {
			return err
		}
		updated, err := v.finish()
		if err != nil {
			return err
		}

		// Update the global and label-specific state.
		labelState.Contact = monitor.Contact.Struct()
		if err := updateRetainedVersions(labelState, v.handle); err != nil {
			return err
		}

		return c.putLabelState(updated, req.Label, labelState, labelTerminal(labelState))
	}
}

func (c *Client) ownerMonitor(
	state *structs.ClientState,
	labelState *structs.ClientLabelState,
	req *structs.OwnerMonitorRequest,
) VerifyFunc[structs.Marshaller] {
	return func(marsh structs.Marshaller) error {
		res, ok := marsh.(*structs.OwnerMonitorResponse)
		if !ok {
			return errors.New("expected owner monitor response, unexpected value received")
		}

		// Verify the proof.
		v, err := newVerifier(c.config, state, res.FullTreeHead, c.now(), req.Last, res.Monitor)
		if err != nil {
			return err
		} else if err := v.addLabelState(labelState); err != nil {
			return err
		} else if err := v.updateView(); err != nil {
			return err
		}
		monitor, err := v.monitor()
		if err != nil {
			return err
		}
		if err := monitor.SetContactState(labelState.Contact); err != nil {
			return err
		} else if err := monitor.SetOwnerState(labelState.Owner); err != nil {
			return err
		}
		if err := monitor.ContactMonitor(); err != nil {
			return err
		} else if err := monitor.OwnerMonitor(); err != nil {
			return err
		}
		updated, err := v.finish()
		if err != nil {
			return err
		}

		// Update the global and label-specific state.
		labelState.Contact = monitor.Contact.Struct()
		labelState.Owner = monitor.Owner.Struct()
		if err := updateRetainedVersions(labelState, v.handle); err != nil {
			return err
		}
		return c.putLabelState(updated, req.Label, labelState, labelTerminal(labelState))
	}
}

// Update returns an UpdateRequest to create new versions of `label` with the
// given `values`. It returns a StreamVerifier that can be used to process a
// stream of UpdateResponse structures.
func (c *Client) Update(label []byte, values [][]byte) (
	*structs.UpdateRequest,
	*StreamVerifier,
	error,
) {
	state, err := c.getState()
	if err != nil {
		return nil, nil, err
	}
	labelState, err := c.getLabelState(label)
	if err != nil {
		return nil, nil, err
	} else if labelState == nil || labelState.Owner == nil {
		return nil, nil, errors.New("label must be owned to be updated")
	}

	labelValues := make([]structs.LabelValue, len(values))
	for i, val := range values {
		labelValues[i] = structs.LabelValue{Value: val}
	}
	req := &structs.UpdateRequest{
		Last: getLast(state),

		Label:           label,
		GreatestVersion: greatestVersion(labelState.Owner),
		Values:          labelValues,
	}
	verifier := &StreamVerifier{
		client:     c,
		state:      state,
		labelState: labelState,
		req:        req,
		pending:    labelValues,
	}
	return req, verifier, nil
}

// StreamVerifier is used to verify a stream of UpdateResponse structures
// without initiating a new request between each one.
type StreamVerifier struct {
	client     *Client
	state      *structs.ClientState
	labelState *structs.ClientLabelState
	req        *structs.UpdateRequest

	// pending contains the values from the UpdateRequest that the Transparency
	// Log has not yet indicated were created. It is cleared once an
	// UpdateResponse indicates that they were.
	pending []structs.LabelValue
}

func (sv *StreamVerifier) verifyValues(
	values []structs.LabelValue,
	res *structs.UpdateResponse,
) (uint32, map[uint32][]byte, error) {
	if len(res.Info) == 0 || len(res.Info) != len(values) {
		return 0, nil, errors.New("unable to process update response")
	}

	startVer := uint32(0)
	if greatest := greatestVersion(sv.labelState.Owner); greatest != nil {
		startVer = *greatest + 1
	}
	commitments := make(map[uint32][]byte)

	for i, val := range values {
		ver := startVer + uint32(i)
		info := res.Info[i]
		update := structs.UpdateValue{Value: val.Value, UpdateSuffix: info.UpdateSuffix}

		// If Third-Party Management is used, verify signature.
		err := verifyUpdateValue(sv.client.config, sv.req.Label, ver, update)
		if err != nil {
			return 0, nil, err
		}

		// Compute commitment for version.
		commitment, err := computeCommitment(sv.client.config, info.Opening, sv.req.Label, ver, update)
		if err != nil {
			return 0, nil, err
		}
		commitments[ver] = commitment
	}

	return startVer, commitments, nil
}

// Verify processes the given UpdateResponse. If it returns an error, the
// StreamVerifier is invalidated and should no longer be used.
func (sv *StreamVerifier) Verify(res *structs.UpdateResponse) error {
	var (
		startVer    uint32
		commitments map[uint32][]byte
		err         error
	)
	if len(res.Values) == 0 {
		startVer, commitments, err = sv.verifyValues(sv.pending, res)
	} else {
		startVer, commitments, err = sv.verifyValues(res.Values, res)
	}
	if err != nil {
		return err
	}

	// Verify that the expected number of entries is present in
	// res.BinaryLadder, and that no commitment is provided for a version
	// greater than or equal to `startVer`.
	ladder := updateLadderVersions(startVer, startVer+uint32(len(res.Info)-1))
	if len(res.BinaryLadder) != len(ladder) {
		return errors.New("incorrect number of binary ladder steps provided")
	}
	for i, ver := range ladder {
		if ver >= startVer && res.BinaryLadder[i].Commitment != nil {
			return errors.New("commitment provided when not expected")
		}
	}

	// Verify the binary ladder and the proof.
	v, err := newVerifier(sv.client.config, sv.state, res.FullTreeHead, sv.client.now(), getLast(sv.state), res.Update)
	if err != nil {
		return err
	} else if err := v.addLabelState(sv.labelState); err != nil {
		return err
	}
	err = v.processLadder(sv.req.Label, res.BinaryLadder, ladder, commitments)
	if err != nil {
		return err
	}

	// Verify the proof.
	if err := v.updateView(); err != nil {
		return err
	}
	monitor, err := v.monitor()
	if err != nil {
		return err
	}
	if err := monitor.SetContactState(sv.labelState.Contact); err != nil {
		return err
	} else if err := monitor.SetOwnerState(sv.labelState.Owner); err != nil {
		return err
	}
	if err := monitor.Update(res.Position, len(res.Info)); err != nil {
		return err
	}
	updated, err := v.finish()
	if err != nil {
		return err
	}

	// Update the global and label-specific state. If the values in our
	// request were created by this response, any later responses in the stream
	// must contain their own values.
	sv.state = updated
	if len(res.Values) == 0 {
		sv.pending = nil
	}
	sv.labelState.Contact = monitor.Contact.Struct()
	sv.labelState.Owner = monitor.Owner.Struct()
	if err := updateRetainedVersions(sv.labelState, v.handle); err != nil {
		return err
	}

	return sv.client.putLabelState(updated, sv.req.Label, sv.labelState, labelTerminal(sv.labelState))
}

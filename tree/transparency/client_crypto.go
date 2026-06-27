package transparency

import (
	"bytes"
	"errors"

	"github.com/Bren2010/katie/crypto/commitments"
	"github.com/Bren2010/katie/tree/transparency/structs"
)

func verifyTreeHead(
	config *structs.PublicConfig,
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
		Config:   config,
		TreeSize: fth.TreeHead.TreeSize,
		Root:     root,
	})
	if err != nil {
		return err
	}
	ok := config.SignatureKey.Verify(tbs, fth.TreeHead.Signature)
	if !ok {
		return errors.New("failed to verify tree head signature")
	} else if fth.AuditorTreeHead == nil {
		return nil
	}

	// Verify size and signature of the auditor tree head.
	if state != nil {
		if state.AuditorTreeHead == nil {
			return errors.New("missing previous auditor tree head")
		} else if state.AuditorTreeHead.TreeSize < config.AuditorStartPos {
			return errors.New("previous auditor tree size does not cover new auditor start position")
		}
	}
	if fth.AuditorTreeHead.Timestamp > rightmost {
		return errors.New("auditor timestamp is greater than rightmost log entry timestamp")
	} else if rightmost-fth.AuditorTreeHead.Timestamp > config.MaxAuditorLag {
		return errors.New("auditor timestamp is too far behind rightmost log entry timestamp")
	} else if fth.AuditorTreeHead.TreeSize > fth.TreeHead.TreeSize {
		return errors.New("auditor tree size is greater than transparency log tree size")
	}

	tbs, err = structs.Marshal(&structs.AuditorTreeHeadTBS{
		Config:    config,
		Timestamp: fth.AuditorTreeHead.Timestamp,
		TreeSize:  fth.AuditorTreeHead.TreeSize,
		Root:      rootP,
	})
	if err != nil {
		return err
	}
	ok = config.AuditorPublicKey.Verify(tbs, fth.TreeHead.Signature)
	if !ok {
		return errors.New("failed to verify auditor signature")
	}

	return nil
}

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

func (c *Client) getState() (*structs.ClientState, error) {
	raw, err := c.tx.GetState()
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

func (c *Client) getLabelState(label []byte) (*structs.ClientLabelState, error) {
	raw, err := c.tx.GetLabelState(label)
	if err != nil {
		return nil, err
	} else if raw == nil {
		return nil, nil
	}

	buf := bytes.NewBuffer(raw)
	state, err := structs.NewClientLabelState(c.config.Suite, buf)
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

func (c *Client) last() (*uint64, error) {
	state, err := c.getState()
	if err != nil {
		return nil, err
	} else if state == nil {
		return nil, nil
	}
	return &state.TreeHead.TreeSize, nil
}

package transparency

import (
	"errors"

	"github.com/Bren2010/katie/tree/log"
	"github.com/Bren2010/katie/tree/transparency/structs"
)

// SetAuditorTreeHead verifies a new tree head from the Third-Party Auditor and,
// if it is valid, commits it to the database so that it is served to users
// going forward. It may only be called in Third-Party Auditing mode.
//
// The tree head must not be older than the one currently held, must cover the
// log entry at AuditorStartPos, and must not cover log entries that don't exist
// yet. Its timestamp must match the timestamp of the last log entry it covers.
func (t *Tree) SetAuditorTreeHead(head *structs.AuditorTreeHead) error {
	if err := t.checkWritable(); err != nil {
		return err
	} else if t.config.Mode != structs.ThirdPartyAuditing {
		return errors.New("auditor tree heads may only be set in third party auditing mode")
	} else if head == nil {
		return errors.New("no auditor tree head provided")
	} else if head.TreeSize <= t.config.AuditorStartPos {
		return errors.New("auditor tree head does not cover auditor start position")
	} else if head.TreeSize > t.n() {
		return errors.New("auditor tree size is greater than transparency log tree size")
	}
	if t.auditorHead != nil {
		if head.TreeSize < t.auditorHead.TreeSize {
			return errors.New("auditor tree size is less than previous auditor tree size")
		} else if head.Timestamp < t.auditorHead.Timestamp {
			return errors.New("auditor timestamp is less than previous auditor timestamp")
		}
	}

	// Check that the auditor's timestamp matches the timestamp of the last log
	// entry it covers.
	results, err := t.tx.BatchGet([]uint64{head.TreeSize - 1})
	if err != nil {
		return err
	} else if results[0] == nil {
		return errors.New("expected log entry not found")
	}
	entry, err := structs.UnmarshalWith(results[0], structs.NewLogEntry, t.config.Suite)
	if err != nil {
		return err
	} else if head.Timestamp != entry.Timestamp {
		return errors.New("auditor timestamp does not match timestamp of log entry")
	}

	// Compute the root of the log tree at the auditor's tree size and verify
	// the auditor's signature over it.
	fullSubtrees, err := log.NewTree(t.config.Suite, t.tx.LogStore()).GetFullSubtrees(head.TreeSize)
	if err != nil {
		return err
	}
	root, err := log.Root(t.config.Suite, head.TreeSize, fullSubtrees)
	if err != nil {
		return err
	}
	tbs, err := structs.Marshal(&structs.AuditorTreeHeadTBS{
		Config:    t.config.Public(),
		Timestamp: head.Timestamp,
		TreeSize:  head.TreeSize,
		Root:      root,
	})
	if err != nil {
		return err
	} else if !t.config.AuditorPublicKey.Verify(tbs, head.Signature) {
		return errors.New("failed to verify auditor signature")
	}

	// Persist the new auditor tree head. The current tree head is written
	// again as well, since every commit must contain one.
	rawTreeHead, err := structs.Marshal(t.treeHead)
	if err != nil {
		return err
	}
	rawAuditorHead, err := structs.Marshal(head)
	if err != nil {
		return err
	}
	t.tx.PutTreeHead(rawTreeHead)
	t.tx.PutAuditorTreeHead(rawAuditorHead)
	if err := t.commit(); err != nil {
		return err
	}

	copied := *head
	t.auditorHead = &copied
	return nil
}

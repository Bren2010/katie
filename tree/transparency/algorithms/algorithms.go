package algorithms

import (
	"errors"
	"time"

	"github.com/Bren2010/katie/tree/transparency/math"
	"github.com/Bren2010/katie/tree/transparency/structs"
)

var (
	ErrLabelNotFound = errors.New("requested version of label does not exist")
	ErrLabelExpired  = errors.New("requested version of label has expired")
)

func noLeftChild(x uint64) bool      { return math.IsLeaf(x) }
func hasLeftChild(x uint64) bool     { return !noLeftChild(x) }
func noRightChild(x, n uint64) bool  { return math.IsLeaf(x) || x == n-1 }
func hasRightChild(x, n uint64) bool { return !noRightChild(x, n) }

// RightmostDistinguished returns the position of the rightmost distinguished
// log entry, or nil if there is none. The public config for the Transparency
// Log is given in `config` and the size of the tree is `n`.
func RightmostDistinguished(config *structs.PublicConfig, n uint64, provider *DataProvider) (*uint64, error) {
	if n == 0 {
		return nil, nil
	}

	// If the root node is not distinguished, then nothing is.
	rightmost, err := provider.GetTimestamp(n - 1)
	if err != nil {
		return nil, err
	} else if !config.IsDistinguished(0, rightmost) {
		return nil, nil
	}

	// Proceed down the frontier until the current node's right child is no
	// longer distinguished.
	x := math.Root(n)
	for {
		if x == n-1 {
			return &x, nil
		}

		timestamp, err := provider.GetTimestamp(x)
		if err != nil {
			return nil, err
		} else if !config.IsDistinguished(timestamp, rightmost) {
			return &x, nil
		}

		x = math.Right(x, n)
	}
}

// PreviousRightmost returns the rightmost distinguished log entry that is to
// the left of the rightmost log entry. This is used when the rightmost log
// entry is being constructed and we need to know which distinguished log
// entries exist to its left.
//
// The public config for the Transparency Log is given in `config`, and the size
// of the tree is `n`.
//
// Note: It is NOT the case that calling PreviousRightmost on a tree of size n
// is equal to calling RightmostDistinguished on a tree of size n-1. This is
// because adding a single log entry can create multiple distinguished log
// entries.
func PreviousRightmost(config *structs.PublicConfig, n uint64, provider *DataProvider) (*uint64, error) {
	rightmost, err := RightmostDistinguished(config, n, provider)
	if err != nil {
		return nil, err
	} else if rightmost == nil || *rightmost != n-1 {
		return rightmost, nil
	}
	var parent *uint64
	if *rightmost != math.Root(n) {
		temp := math.Parent(*rightmost, n)
		parent = &temp
	}

	// Compute bounds to use for determining distinguished status.
	left := uint64(0)
	if parent != nil {
		left, err = provider.GetTimestamp(*parent)
		if err != nil {
			return nil, err
		}
	}
	right, err := provider.GetTimestamp(*rightmost)
	if err != nil {
		return nil, err
	}

	// If the rightmost distinguished log entry has a left child and the left
	// child is distinguished, then there's a subtree of distinguished log
	// entries. Find it's rightmost edge.
	if hasLeftChild(*rightmost) && config.IsDistinguished(left, right) {
		out := math.Left(*rightmost)
		for {
			if noRightChild(out, n) {
				return &out, nil
			}
			left, err = provider.GetTimestamp(out)
			if err != nil {
				return nil, err
			} else if !config.IsDistinguished(left, right) {
				return &out, nil
			}
			out = math.Right(out, n)
		}
	}

	// Otherwise return the rightmost distinguished log entry's parent, which
	// will be distinguished and to its left.
	return parent, nil
}

// UpdateView runs the algorithm from Section 4.2. The previous size of the tree
// is `m`, the current size of the tree is `n`.
func UpdateView(config *structs.PublicConfig, n uint64, m *uint64, provider *DataProvider) error {
	if m != nil && *m > n {
		return errors.New("new tree size is not greater than previous tree size")
	} else if n == 0 {
		return nil
	}

	for _, x := range math.UpdateView(n, m) {
		if _, err := provider.GetTimestamp(x); err != nil {
			return err
		}
	}

	now := uint64(time.Now().UnixMilli())
	ts, err := provider.GetTimestamp(n - 1)
	if err != nil {
		return err
	} else if now < ts && ts-now > config.MaxAhead {
		return errors.New("rightmost timestamp is too far ahead of local clock")
	} else if now > ts && now-ts > config.MaxBehind {
		return errors.New("rightmost timestamp is too far behind local clock")
	}

	return nil
}

package transparency

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

// rightmostDistinguished returns the position of the rightmost distinguished
// log entry, or nil if there is none. The public config for the Transparency
// Log is given in `config` and the size of the tree is `n`.
func rightmostDistinguished(config *structs.PublicConfig, n uint64, provider *dataProvider) (*uint64, error) {
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

// updateView runs the algorithm from Section 4.2. The previous size of the tree
// is `m`, the current size of the tree is `n`.
func updateView(config *structs.PublicConfig, n uint64, m *uint64, provider *dataProvider) error {
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

// greatestVersionSearch runs the algorithm from Section 6.3. The public config
// for the Transparency Log is given in `config`, the claimed greatest version
// of the label is `ver`, and the size of the tree is `n`.
//
// It returns the position of the terminal node of the search.
func greatestVersionSearch(config *structs.PublicConfig, ver uint32, n uint64, provider *dataProvider) (uint64, error) {
	if n == 0 {
		return 0, errors.New("unable to search empty tree")
	}

	// Identify the starting position for the search. This is either the
	// rightmost distinguished log entry, or the root if there are no
	// distinguished log entries.
	rightmostDLE, err := rightmostDistinguished(config, n, provider)
	if err != nil {
		return 0, nil
	}
	var x uint64
	if rightmostDLE != nil {
		x = *rightmostDLE
	} else {
		x = math.Root(n)
	}

	// From the starting position, move down the remainder of the frontier.
	terminal, first := uint64(0), true
	for {
		res, err := provider.GetSearchBinaryLadder(x, ver, true)
		if err != nil {
			return 0, err
		}
		if res == 0 && first {
			terminal = x
			first = false
		}
		if x != n-1 {
			x = math.Right(x, n)
			continue
		}
		if res != 0 {
			return 0, errors.New("rightmost log entry not consistent with claimed greatest version of label")
		}
		return terminal, nil
	}
}

// fixedVersionSearch runs the algorithm from Section 7.2. The public config for
// the Transparency Log is given in `config`, the target version of the search
// is `ver`, and the size of the tree is `n`.
//
// It returns the position of the terminal node of the search.
func fixedVersionSearch(config *structs.PublicConfig, ver uint32, n uint64, provider *dataProvider) (uint64, error) {
	rightmost, err := provider.GetTimestamp(n - 1)
	if err != nil {
		return 0, err
	}

	var (
		terminalFound = false     // Whether a potential terminal log entry has been seen.
		terminalPos   = uint64(0) // Position of the terminal log entry.

		expired                = false        // Whether any expired log entries are in the search path.
		left, right   uint64   = 0, rightmost // Bounds for determining distinguished status.
		distinguished []uint64                // Distinguished unexpired log entries in search path.
	)
	finish := func() (uint64, error) {
		if !terminalFound { // If there is no terminal log entry, return an error.
			return 0, ErrLabelNotFound
		} else if expired { // If any expired log entries were encountered,
			// Determine if the terminal log entry is to the left of the
			// leftmost unexpired distinguished log entry.
			found := false
			for _, y := range distinguished {
				if y < terminalPos {
					found = true
					break
				}
			}
			if !found { // If so, return an error.
				return 0, ErrLabelExpired
			}
		} // Otherwise, look up the target version specifically.
		if err := provider.GetInclusionProof(terminalPos, ver); err != nil {
			return 0, err
		}
		return terminalPos, nil
	}

	x := math.Root(n)
	for {
		timestamp, err := provider.GetTimestamp(x)
		if err != nil {
			return 0, err
		}

		// If the log entry is expired, recurse to its right child.
		if config.IsExpired(timestamp, rightmost) {
			expired = true
			if math.IsLeaf(x) {
				return finish()
			}
			x, left = math.Right(x, n), timestamp
			continue
		} else if config.IsDistinguished(left, right) {
			distinguished = append(distinguished, x)
		}

		// Obtain a search binary ladder from the current log entry.
		res, err := provider.GetSearchBinaryLadder(x, ver, true)
		if err != nil {
			return 0, err
		} else if res >= 0 && (!terminalFound || x < terminalPos) {
			terminalFound, terminalPos = true, x
		}

		// If the binary ladder indicates a greatest version less than the
		// target version, then recurse to the right child.
		if res == -1 {
			if math.IsLeaf(x) || x == n-1 {
				return finish()
			}
			x, left = math.Right(x, n), timestamp
			continue
		}

		// If the binary ladder indicates a greatest version greater than the
		// target, then recurse to the left child.
		if res == 1 {
			if math.IsLeaf(x) {
				return finish()
			}
			x, right = math.Left(x), timestamp
			continue
		}

		// If the binary ladder indicates a greatest version equal to the target
		// version, then:
		if !expired { // If there were no expired log entries, terminate successfully.
			return terminalPos, nil
		}
		// Determine whether this log entry, or any unexpired log entries in
		// its direct path and to its left, are distinguished.
		for _, y := range distinguished {
			if y <= x { // If so, terminate successfully.
				return terminalPos, nil
			}
		} // Otherwise, return an error that the target version is expired.
		return 0, ErrLabelExpired
	}
}

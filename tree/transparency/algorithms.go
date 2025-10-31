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
// Log is given in `config`, and the size of the tree is `n`.
func rightmostDistinguished(config *structs.PublicConfig, n uint64, provider *dataProvider) (*uint64, error) {
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

		right := math.Right(x, n)
		timestamp, err := provider.GetTimestamp(right)
		if err != nil {
			return nil, err
		} else if !config.IsDistinguished(timestamp, rightmost) {
			return &x, nil
		}

		x = right
	}
}

// updateView runs the algorithm from Section 4.2. The previous size of the tree
// is `m`, the current size of the tree is `n`.
func updateView(config *structs.PublicConfig, n uint64, m *uint64, provider *dataProvider) error {
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

// fixedVersionSearch runs the algorithm from Section 6.3. The public config for
// the Transparency Log is given in `config`, the target version of the search
// is `ver`, and the size of the tree is `n`.
//
// It returns the position of the terminal node of the search.
func fixedVersionSearch(config *structs.PublicConfig, ver uint32, n uint64, provider *dataProvider) (uint64, error) {
	rightmost, err := provider.GetTimestamp(n - 1)
	if err != nil {
		return 0, err
	}

	type terminalLogEntry struct {
		position uint64
		expired  bool
	}
	var terminal *terminalLogEntry
	finish := func() (uint64, error) {
		if terminal == nil { // If there is no terminal log entry, return an error.
			return 0, ErrLabelNotFound
		} else if terminal.expired { // If the log entry is expired, return an error.
			return 0, ErrLabelExpired
		} else if err := provider.GetInclusionProof(terminal.position, ver); err != nil {
			return 0, err
		}
		return terminal.position, nil
	}

	x, frontier := math.Root(n), true
	for {
		timestamp, err := provider.GetTimestamp(x)
		if err != nil {
			return 0, err
		}

		// If the log entry is expired, is on the frontier, and its right child
		// is also expired, recurse to the right child.
		if config.IsExpired(timestamp, rightmost) && frontier {
			right := math.Right(x, n)
			ts, err := provider.GetTimestamp(right)
			if err != nil {
				return 0, err
			} else if config.IsExpired(ts, rightmost) {
				x = right
				continue
			}
		}

		// Obtain a search binary ladder from the current log entry.
		res, err := provider.GetSearchBinaryLadder(x, ver, true)
		if err != nil {
			return 0, err
		}
		if res >= 0 && (terminal == nil || x < terminal.position) {
			terminal = &terminalLogEntry{
				position: x,
				expired:  config.IsExpired(timestamp, rightmost),
			}
		}

		// If the binary ladder indicates a greatest version less than the
		// target version, then:
		if res == -1 {
			if math.IsLeaf(x) || x == n-1 { // If no right child, go to step 6.
				return finish()
			} // Otherwise, recurse to the right child.
			x = math.Right(x, n)
			continue
		}

		// If the binary ladder indicates a greatest version equal to the target
		// version, then:
		if res == 0 {
			if !config.IsExpired(timestamp, rightmost) { // If not expired, terminate.
				return x, nil
			} else if math.IsLeaf(x) || x == n-1 { // If no right child, go to step 6.
				return finish()
			} // Otherwise, recurse to the right child.
			x = math.Right(x, n)
			continue
		}

		// If the binary ladder indicates a greatest version greater than the
		// target, then:
		if res == 1 {
			if math.IsLeaf(x) { // If no left child, go to step 6.
				return finish()
			} else if config.IsExpired(timestamp, rightmost) { // If expired, return an error.
				return 0, ErrLabelExpired
			} // Otherwise, recurse to the left child.
			x, frontier = math.Left(x), false
			continue
		}

		panic("unreachable")
	}
}

// greatestVersionSearch runs the algorithm from Section 7.2. The public config
// for the Transparency Log is given in `config`, and the size of the tree is
// `n`.
//
// It returns the position of the terminal node of the search.
func greatestVersionSearch(config *structs.PublicConfig, ver uint32, n uint64, provider *dataProvider) (uint64, error) {
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

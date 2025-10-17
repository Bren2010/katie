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
// It returns whether or not contact monitoring may be required, and the
// position of the terminal node of the search.
func fixedVersionSearch(config *structs.PublicConfig, ver uint32, n uint64, provider *dataProvider) (bool, uint64, error) {
	rightmost, err := provider.GetTimestamp(n - 1)
	if err != nil {
		return false, 0, err
	}

	type terminalLogEntry struct {
		position      uint64
		expired       bool
		distinguished bool
	}
	var terminal *terminalLogEntry
	finish := func() (bool, uint64, error) {
		if terminal == nil { // If there is no terminal log entry, return an error.
			return false, 0, ErrLabelNotFound
		} else if terminal.expired { // If the log entry is expired, return an error.
			return false, 0, ErrLabelExpired
		} else if err := provider.GetInclusionProof(terminal.position, ver); err != nil {
			return false, 0, err
		}
		return !terminal.distinguished, terminal.position, nil
	}

	var (
		x              = math.Root(n)
		frontier       = true
		leftTimestamp  = uint64(0)
		rightTimestamp = rightmost
	)
	for {
		timestamp, err := provider.GetTimestamp(x)
		if err != nil {
			return false, 0, err
		}

		// If the log entry is expired, is on the frontier, and its right child
		// is also expired, recurse to the right child.
		if config.IsExpired(timestamp, rightmost) && frontier {
			right := math.Right(x, n)
			ts, err := provider.GetTimestamp(right)
			if err != nil {
				return false, 0, err
			} else if config.IsExpired(ts, rightmost) {
				x, leftTimestamp = right, timestamp
				continue
			}
		}

		// Obtain a search binary ladder from the current log entry.
		res, err := provider.GetSearchBinaryLadder(x, ver, true)
		if err != nil {
			return false, 0, err
		}
		if res >= 0 && (terminal == nil || x < terminal.position) {
			terminal = &terminalLogEntry{
				position:      x,
				expired:       config.IsExpired(timestamp, rightmost),
				distinguished: config.IsDistinguished(leftTimestamp, rightTimestamp),
			}
		}

		// If the binary ladder indicates a greatest version less than the
		// target version, then:
		if res == -1 {
			if math.IsLeaf(x) || x == n-1 { // If no right child, go to step 6.
				return finish()
			} // Otherwise, recurse to the right child.
			x, leftTimestamp = math.Right(x, n), timestamp
			continue
		}

		// If the binary ladder indicates a greatest version equal to the target
		// version, then:
		if res == 0 {
			if !config.IsExpired(timestamp, rightmost) { // If not expired, terminate.
				return !config.IsDistinguished(leftTimestamp, rightTimestamp), x, nil
			} else if math.IsLeaf(x) || x == n-1 { // If no right child, go to step 6.
				return finish()
			} // Otherwise, recurse to the right child.
			x, leftTimestamp = math.Right(x, n), timestamp
			continue
		}

		// If the binary ladder indicates a greatest version greater than the
		// target, then:
		if res == 1 {
			if math.IsLeaf(x) { // If no left child, go to step 6.
				return finish()
			} else if config.IsExpired(timestamp, rightmost) { // If expired, return an error.
				return false, 0, ErrLabelExpired
			} // Otherwise, recurse to the left child.
			x, frontier, rightTimestamp = math.Left(x), false, timestamp
			continue
		}

		panic("unreachable")
	}
}

// greatestVersionSearch runs the algorithm from Section 7.2. The public config
// for the Transparency Log is given in `config`, and the size of the tree is
// `n`.
//
// It returns whether or not contact monitoring may be required, and the
// position of the terminal node of the search.
func greatestVersionSearch(config *structs.PublicConfig, ver uint32, n uint64, provider *dataProvider) (bool, uint64, error) {
	// Identify the starting position for the search. This is either the
	// rightmost distinguished log entry, or the root if there are no
	// distinguished log entries.
	rightmost, err := provider.GetTimestamp(n - 1)
	if err != nil {
		return false, 0, err
	}
	start := math.Root(n)

	rootDistinguished := config.IsDistinguished(0, rightmost)
	if rootDistinguished {
		timestamp, err := provider.GetTimestamp(start)
		if err != nil {
			return false, 0, err
		}
		for start != n-1 && config.IsDistinguished(timestamp, rightmost) {
			start = math.Right(start, n)
		}
	}

	// From the starting position, move down the remainder of the frontier.
	x := start
	terminal, first := uint64(0), true
	for {
		res, err := provider.GetSearchBinaryLadder(x, ver, true)
		if err != nil {
			return false, 0, err
		}
		if res == 0 && first {
			terminal = x
			first = false
		}
		if x < n-1 {
			x = math.Right(x, n)
			continue
		}
		if res != 0 {
			return false, 0, errors.New("rightmost log entry not consistent with claimed greatest version of label")
		}
		return !rootDistinguished || terminal != start, terminal, nil
	}
}

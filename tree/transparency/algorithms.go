package transparency

import (
	"errors"

	"github.com/Bren2010/katie/tree/transparency/math"
	"github.com/Bren2010/katie/tree/transparency/structs"
)

var (
	ErrLabelNotAvailable = errors.New("requested version of label has expired and is no longer available")
)

type dataProvider interface {
	// GetTimestamp takes as input the position of a log entry and returns the
	// timestamp of the log entry. This function verifies that the timestamp is
	// monotonic with others provided or retained.
	GetTimestamp(x uint64) (uint64, error)

	// GetSearchBinaryLadder takes as input the position of a log entry, the
	// target version for a search binary ladder, and whether or not to omit
	// redundant lookups. It returns -1, 0, or 1 to indicate whether the
	// greatest version of the label proven to exist is less than, equal to, or
	// greater than the target version, respectively.
	GetSearchBinaryLadder(x uint64, ver uint32, omit bool) (int, error)

	// GetMonitoringBinaryLadder takes as input the position of a log entry and
	// the target version for a monitoring binary ladder.
	GetMonitoringBinaryLadder(x uint64, ver uint32) error
}

// updateView runs the algorithm from Section 4.2. The previous size of the tree
// is `m`, the current size of the tree is `n`, and the rightmost timestamp of
// the previous view of the tree is `mTimestamp` (or 0 if none). It returns the
// new rightmost timestamp.
func updateView(m, n, mTimestamp uint64, provider dataProvider) (uint64, error) {
	prev := mTimestamp

	for _, x := range math.UpdateView(m, n) {
		timestamp, err := provider.GetTimestamp(x)
		if err != nil {
			return 0, err
		} else if timestamp < prev {
			return 0, errors.New("timestamps are not monotonic")
		}
		prev = timestamp
	}

	return prev, nil
}

func fixedVersionSearch(config *structs.PublicConfig, n uint64, provider dataProvider) error {
	x := math.Root(n)

	rightmostTimestamp, err := provider.GetTimestamp(n - 1)
	if err != nil {
		return err
	}
	pastMaxLifetime := func(t uint64) bool {
		return t-rightmostTimestamp >= config.MaximumLifetime
	}
	lowerTimestamp := uint64(0)
	upperTimestamp := uint64((1 << 64) - 1)

	results := make(map[uint64]bool)
	finishSearch := func() error { return nil }

	for {
		// Verify that the log entry's timestamp is consistent with the
		// timestamps of all ancestor log entries.
		timestamp, err := provider.GetTimestamp(x)
		if err != nil {
			return err
		} else if timestamp < lowerTimestamp || timestamp > upperTimestamp {
			return errors.New("timestamps are not monotonic")
		}

		// If the log entry is past its Maximum Lifetime, is on the frontier,
		// and its right child is also past its maximum lifetime, recurse right.
		if pastMaxLifetime(timestamp) {
			right := math.Right(x, n)
			childTimestamp, err := provider.GetTimestamp(right)
			if err != nil {
				return err
			} else if pastMaxLifetime(childTimestamp) {
				x, lowerTimestamp = right, timestamp
				continue
			}
		}

		// Obtain a binary ladder from the current log entry.
		present, err := provider.GetPrefixProof(x)
		if err != nil {
			return err
		}
		results[x] = present

		// If the binary ladder terminated early due to non-inclusion of a
		// version less than or equal to the target version, recurse right.
		if !present {
			if math.IsLeaf(x) {
				return finishSearch()
			}
			x, lowerTimestamp = math.Right(x, n), timestamp
			continue
		}

		// Check if the log entry has surpassed its maximum lifetime. If so,
		// abort the search with an error. If not, recurse left.
		if pastMaxLifetime(timestamp) {
			return ErrLabelNotAvailable
		} else if math.IsLeaf(x) {
			return finishSearch()
		}
		x, upperTimestamp = math.Left(x), timestamp
	}
}

// greatestVersionSearch runs the algorithm from Section 7.2. The public config
// for the Transparency Log is given in `config`, and the size of the tree is
// `n`.
//
// It returns whether or not contact monitoring may be required, and the
// position of the terminal node of the search.
func greatestVersionSearch(config *structs.PublicConfig, ver uint32, n uint64, provider dataProvider) (bool, uint64, error) {
	isDistinguished := func(left, right uint64) bool {
		return right-left >= config.ReasonableMonitoringWindow
	}

	// Identify the starting position for the search. This is either the
	// rightmost distinguished log entry, or the root if there are no
	// distinguished log entries.
	rightmost, err := provider.GetTimestamp(n - 1)
	if err != nil {
		return false, 0, err
	}
	start := math.Root(n)

	rootDistinguished := isDistinguished(0, rightmost)
	if rootDistinguished {
		timestamp, err := provider.GetTimestamp(start)
		if err != nil {
			return false, 0, err
		}
		for start != n-1 && isDistinguished(timestamp, rightmost) {
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

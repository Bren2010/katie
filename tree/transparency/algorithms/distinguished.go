package algorithms

import (
	"bytes"
	"errors"
	"slices"

	"github.com/Bren2010/katie/tree/transparency/math"
	"github.com/Bren2010/katie/tree/transparency/structs"
)

// RecentFunc returns whether a distinguished log entry meets the application's
// definition of "recent". See structs.RecentFunc.
type RecentFunc = structs.RecentFunc

// RecentCount returns a RecentFunc where a distinguished log entry is recent if
// it is one of the `n` rightmost.
func RecentCount(n int) RecentFunc {
	return func(_, _, _ uint64, count int) bool { return count < n }
}

// RecentWithin returns a RecentFunc where a distinguished log entry is recent
// if subtracting its timestamp from the timestamp of the rightmost log entry
// yields a value less than `threshold`.
func RecentWithin(threshold uint64) RecentFunc {
	return func(_, timestamp, rightmost uint64, _ int) bool {
		return rightmost-timestamp < threshold
	}
}

type distinguishedWalker struct {
	config    *structs.PublicConfig
	stop      *uint64
	recent    RecentFunc
	n         uint64
	provider  *DataProvider
	rightmost uint64

	found []uint64 // Recent distinguished log entries, from right to left.
}

// walk executes the recursive algorithm from Section 10.1, starting at log
// entry `x`. `left` and `right` are the bounds used for determining
// distinguished status.
func (w *distinguishedWalker) walk(x, left, right uint64) error {
	// If the current log entry is not distinguished, stop.
	if !w.config.IsDistinguished(left, right) {
		return nil
	}
	timestamp, err := w.provider.GetTimestamp(x)
	if err != nil {
		return err
	}

	// If the current log entry has a right child, recurse to the right child.
	if hasRightChild(x, w.n) {
		if err := w.walk(math.Right(x, w.n), timestamp, right); err != nil {
			return err
		}
	}

	// If a stopping position was provided and the current log entry's position
	// is less than or equal to it, stop.
	if w.stop != nil && x <= *w.stop {
		return nil
	}

	// If the current log entry isn't recent, stop. Expired log entries are
	// never considered recent.
	if w.config.IsExpired(timestamp, w.rightmost) ||
		!w.recent(x, timestamp, w.rightmost, len(w.found)) {
		return nil
	}
	w.found = append(w.found, x)

	// If the current log entry has a left child, recurse to the left child.
	if hasLeftChild(x) {
		return w.walk(math.Left(x), left, timestamp)
	}
	return nil
}

// WalkDistinguished runs the algorithm from Section 10.1. The public config for
// the Transparency Log is given in `config`, the optional stopping position is
// `stop`, the application's definition of "recent" is `recent`, and the size of
// the tree is `n`.
//
// It returns the positions of the recent distinguished log entries in
// left-to-right order.
func WalkDistinguished(
	config *structs.PublicConfig,
	stop *uint64,
	recent RecentFunc,
	n uint64,
	provider *DataProvider,
) ([]uint64, error) {
	if stop != nil && *stop >= n {
		return nil, errors.New("stopping position is not in tree")
	} else if n == 0 {
		return nil, nil
	}
	rightmost, err := provider.GetTimestamp(n - 1)
	if err != nil {
		return nil, err
	}

	w := &distinguishedWalker{
		config:    config,
		stop:      stop,
		recent:    recent,
		n:         n,
		provider:  provider,
		rightmost: rightmost,
	}
	if err := w.walk(math.Root(n), 0, rightmost); err != nil {
		return nil, err
	}
	slices.Reverse(w.found)

	return w.found, nil
}

// CompareRoots verifies that two lists of log tree root values, each in
// left-to-right order, are consistent with each other. That is, that each list
// is either a prefix or a suffix of the other, having at least one root value
// in common.
//
// Algorithm from Section 10.2.
func CompareRoots(a, b [][]byte) error {
	if len(a) != len(b) {
		return errors.New("lists must be the same size")
	}
	n := len(a)

	for x := range n {
		if slices.EqualFunc(a[:n-x], b[x:], bytes.Equal) ||
			slices.EqualFunc(b[:n-x], a[x:], bytes.Equal) {
			return nil
		}
	}

	return errors.New("no valid overlap found")
}

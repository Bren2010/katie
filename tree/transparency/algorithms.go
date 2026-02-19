package transparency

import (
	"errors"
	"slices"
	"time"

	"github.com/Bren2010/katie/tree/transparency/math"
	"github.com/Bren2010/katie/tree/transparency/structs"
)

var (
	ErrLabelNotFound = errors.New("requested version of label does not exist")
	ErrLabelExpired  = errors.New("requested version of label has expired")
)

func noLeftChild(x uint64) bool     { return math.IsLeaf(x) }
func noRightChild(x, n uint64) bool { return math.IsLeaf(x) || x == n-1 }

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
		} else if res == 1 {
			return 0, errors.New("log entry not consistent with claimed greatest version of label")
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
	if n == 0 {
		return 0, errors.New("unable to search empty tree")
	}
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
			if noRightChild(x, n) {
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
			if noRightChild(x, n) {
				return finish()
			}
			x, left = math.Right(x, n), timestamp
			continue
		}

		// If the binary ladder indicates a greatest version greater than the
		// target, then recurse to the left child.
		if res == 1 {
			if noLeftChild(x) {
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

type ownerState struct {
	// starting is the position of the rightmost distinguished log entry that
	// has been verified by owner monitoring.
	starting uint64

	// verAtStarting is the version of the label that exists at `starting`, or
	// -1 if the label didn't exist yet.
	verAtStarting int
	// upcomingVers is the position of each upcoming new version of the label.
	upcomingVers []uint64
}

func (os *ownerState) setStarting(x uint64) {
	idx, _ := slices.BinarySearch(os.upcomingVers, x+1)

	os.starting = x
	os.verAtStarting = idx + os.verAtStarting
	os.upcomingVers = os.upcomingVers[idx:]
}

func (os *ownerState) greatestVersionAt(x uint64) int {
	idx, _ := slices.BinarySearch(os.upcomingVers, x+1)
	return idx + os.verAtStarting
}

// monitoringReq contains the fixed portions of the state of a monitoring
// request so that it is easier to pass into recursive functions.
type monitoringReq struct {
	config    *structs.PublicConfig
	state     *ownerState
	rightmost uint64
	n         uint64

	provider *dataProvider
}

// init returns the list of log entries to verify if an owner is starting their
// monitoring at `req.state.starting`. `x` is the current log entry, and `left`
// and `right` are the bounds used to determine distinguished status.
//
// Algorithm from the first portion of Section 8.3.
func (req *monitoringReq) init(x, left, right uint64) ([]uint64, error) {
	if !req.config.IsDistinguished(left, right) {
		return nil, errors.New("requested starting position is not distinguished")
	}
	timestamp, err := req.provider.GetTimestamp(x)
	if err != nil {
		return nil, err
	}
	isExpired := req.config.IsExpired(timestamp, req.rightmost)

	if x < req.state.starting {
		// Starting position is to our right, so recurse right.
		if noRightChild(x, req.n) {
			return nil, errors.New("requested starting position is right of the rightmost log entry")
		}
		children, err := req.init(math.Right(x, req.n), timestamp, right)
		if err != nil {
			return nil, err
		} else if isExpired {
			return children, nil
		}
		return append(children, x), nil
	} else if x == req.state.starting {
		// We've reached the requested starting position. We already know it's
		// distinguished and just need to verify that it's unexpired.
		if isExpired {
			return nil, errors.New("requested starting position is expired")
		}
		return []uint64{x}, nil
	}
	// Starting position is to our left, so recurse left.
	if noLeftChild(x) || isExpired {
		return nil, errors.New("requested starting position is invalid")
	}
	return req.init(math.Left(x), left, timestamp)
}

// monitor performs a depth-first walk of every unexpired distinguished log
// entry that is to the right of `req.state.starting`, and requests a search
// binary ladder from each of them for the expected greatest version of the
// label.
//
// Algorithm from the second portion of Section 8.3.
func (req *monitoringReq) monitor(x, left, right uint64) error {
	// If the current log entry is not distinguished, stop.
	if !req.config.IsDistinguished(left, right) {
		return nil
	}

	// If the current log entry's index is less than or equal to that of the log
	// entry advertised by the user, recurse to its right child.
	if x <= req.state.starting {
		if noRightChild(x, req.n) {
			return nil
		}
		timestamp, err := req.provider.GetTimestamp(x)
		if err != nil {
			return err
		}
		return req.monitor(math.Right(x, req.n), timestamp, right)
	}

	// If the current log entry has a left child, recurse to the left child.
	if !noLeftChild(x) {
		timestamp, err := req.provider.GetTimestamp(x)
		if err != nil {
			return err
		}
		if err := req.monitor(math.Left(x), left, timestamp); err != nil {
			return err
		}
	}

	// If a stop condition has been reached, stop.
	if req.provider.StopCondition(x, req.state.greatestVersionAt(x)) {
		return nil
	}

	// Obtain a search binary ladder from the current log entry where the target
	// version is the greatest version of the label expected to exist at this
	// point, based on the label owner's state.
	ver := req.state.greatestVersionAt(x)
	if ver < 0 {
		res, err := req.provider.GetSearchBinaryLadder(x, 0, false)
		if err != nil {
			return err
		} else if res != -1 {
			return errors.New("binary ladder inconsistent with expected greatest version of label")
		}
	} else {
		res, err := req.provider.GetSearchBinaryLadder(x, uint32(ver), false)
		if err != nil {
			return err
		} else if res != 0 {
			return errors.New("binary ladder inconsistent with expected greatest version of label")
		}
	}

	// If the current log entry has a right child, recurse to the right child.
	if noRightChild(x, req.n) {
		return nil
	}
	timestamp, err := req.provider.GetTimestamp(x)
	if err != nil {
		return err
	}
	return req.monitor(math.Right(x, req.n), timestamp, right)
}

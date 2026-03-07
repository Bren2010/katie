package algorithms

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

	left := uint64(0) // Bound used for determining distinguished status.
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

// GreatestVersionSearch runs the algorithm from Section 6.3. The public config
// for the Transparency Log is given in `config`, the claimed greatest version
// of the label is `ver`, and the size of the tree is `n`.
//
// It returns the position of the terminal node of the search.
func GreatestVersionSearch(config *structs.PublicConfig, ver uint32, n uint64, provider *DataProvider) (uint64, error) {
	if n == 0 {
		return 0, errors.New("unable to search empty tree")
	}

	// Identify the starting position for the search. This is either the
	// rightmost distinguished log entry, or the root if there are no
	// distinguished log entries.
	rightmostDLE, err := RightmostDistinguished(config, n, provider)
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
		if ver == 0 && res == -1 {
			return 0, ErrLabelNotFound
		} else if res != 0 {
			return 0, errors.New("rightmost log entry not consistent with claimed greatest version of label")
		}
		return terminal, nil
	}
}

// FixedVersionSearch runs the algorithm from Section 7.2. The public config for
// the Transparency Log is given in `config`, the target version of the search
// is `ver`, and the size of the tree is `n`.
//
// It returns the position of the terminal node of the search.
func FixedVersionSearch(config *structs.PublicConfig, ver uint32, n uint64, provider *DataProvider) (uint64, error) {
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

// OwnerState wraps the state maintained by the owner of a single label.
type OwnerState struct {
	// Starting is the position of the rightmost distinguished log entry that
	// has been verified by owner monitoring.
	Starting uint64

	// VerAtStarting is the version of the label that exists at `starting`, or
	// -1 if the label didn't exist yet.
	VerAtStarting int
	// UpcomingVers is the position of each upcoming new version of the label.
	UpcomingVers []uint64
}

func (os *OwnerState) setStarting(x uint64) {
	idx, _ := slices.BinarySearch(os.UpcomingVers, x+1)

	os.Starting = x
	os.VerAtStarting = idx + os.VerAtStarting
	os.UpcomingVers = os.UpcomingVers[idx:]
}

func (os *OwnerState) greatestVersionAt(x uint64) int {
	idx, _ := slices.BinarySearch(os.UpcomingVers, x+1)
	return idx + os.VerAtStarting
}

// Owner represents the owner of a single label and provides methods for
// monitoring that label.
type Owner struct {
	config    *structs.PublicConfig
	state     *OwnerState
	rightmost uint64 // Timestamp of rightmost log entry.
	n         uint64 // Number of log entries.

	provider *DataProvider
}

// NewOwner returns a new Owner. The public config for the Transparency Log is
// `config`, the owner's state (or nil, if the owner has not been initialized
// yet) is `state`, and the size of the tree is `n`.
func NewOwner(config *structs.PublicConfig, state *OwnerState, n uint64, provider *DataProvider) (*Owner, error) {
	if n == 0 {
		return nil, errors.New("unable to monitor empty tree")
	}
	rightmost, err := provider.GetTimestamp(n - 1)
	if err != nil {
		return nil, err
	}

	return &Owner{
		config:    config,
		state:     state,
		rightmost: rightmost,
		n:         n,

		provider: provider,
	}, nil
}

func (owner *Owner) State() *OwnerState { return owner.state }

// init returns the list of log entries to verify if an owner is starting their
// monitoring at `starting`. `x` is the current log entry, and `left` and
// `right` are the bounds used to determine distinguished status.
func (owner *Owner) init(starting, x, left, right uint64) ([]uint64, error) {
	if !owner.config.IsDistinguished(left, right) {
		return nil, errors.New("requested starting position is not distinguished")
	}
	timestamp, err := owner.provider.GetTimestamp(x)
	if err != nil {
		return nil, err
	}
	isExpired := owner.config.IsExpired(timestamp, owner.rightmost)

	if x < starting {
		// Starting position is to our right, so recurse right.
		if noRightChild(x, owner.n) {
			return nil, errors.New("requested starting position is right of the rightmost log entry")
		}
		children, err := owner.init(starting, math.Right(x, owner.n), timestamp, right)
		if err != nil {
			return nil, err
		} else if isExpired {
			return children, nil
		}
		return append(children, x), nil
	} else if x == starting {
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
	return owner.init(starting, math.Left(x), left, timestamp)
}

// InitEntries returns the log entries that will be inspected while initializing
// the owner's state with a starting position of `starting` (done in Init).
func (owner *Owner) InitEntries(starting uint64) ([]uint64, error) {
	return owner.init(starting, math.Root(owner.n), 0, owner.rightmost)
}

// Init initializes the label owner's state. `starting` contains the log entry
// where the label owner wants their ownership to start, and `vers` contains the
// version of the label that exists at each log entry returned by `InitEntries`.
//
// Algorithm from the first portion of Section 8.3.
func (owner *Owner) Init(starting uint64, vers []uint32) error {
	if owner.state != nil {
		return errors.New("label owner state is already initialized")
	}
	xs, err := owner.InitEntries(starting)
	if err != nil {
		return err
	}

	// Verify that the expected number of versions was provided and that each
	// version is less than or equal to the one prior.
	if len(vers) > len(xs) {
		return errors.New("unexpected number of versions provided to owner initialization algorithm")
	}
	for i := 1; i < len(vers); i++ {
		if vers[i] > vers[i-1] {
			return errors.New("unexpected increase in label version")
		}
	}

	// Obtain a search binary ladder from each log entry in `xs`. Verify that
	// the ladder terminates in a way that is consistent with the version
	// provided in `vers`.
	for i, x := range xs {
		if i < len(vers) {
			res, err := owner.provider.GetSearchBinaryLadder(x, vers[i], false)
			if err != nil {
				return err
			} else if res != 0 {
				return errors.New("binary ladder inconsistent with expected greatest version of label")
			}
		} else {
			res, err := owner.provider.GetSearchBinaryLadder(x, 0, false)
			if err != nil {
				return err
			} else if res != -1 {
				return errors.New("binary ladder inconsistent with expected greatest version of label")
			}
		}
	}

	// Setup OwnerState object.
	verAtStarting := -1
	if len(vers) > 0 {
		verAtStarting = int(vers[0])
	}
	owner.state = &OwnerState{starting, verAtStarting, nil}

	return nil
}

// monitor performs a depth-first walk of every unexpired distinguished log
// entry that is to the right of `owner.state.Starting`, and requests a search
// binary ladder from each of them for the expected greatest version of the
// label. `x` is the current log entry, `left` and `right` are the bounds used
// for determining distinguished status.
func (owner *Owner) monitor(x, left, right uint64) error {
	// If the current log entry is not distinguished, stop.
	if !owner.config.IsDistinguished(left, right) {
		return nil
	}

	// If the current log entry's index is less than or equal to that of the log
	// entry advertised by the user, recurse to its right child.
	if x <= owner.state.Starting {
		if noRightChild(x, owner.n) {
			return nil
		}
		timestamp, err := owner.provider.GetTimestamp(x)
		if err != nil {
			return err
		}
		return owner.monitor(math.Right(x, owner.n), timestamp, right)
	}

	// If the current log entry has a left child, recurse to the left child.
	if hasLeftChild(x) {
		timestamp, err := owner.provider.GetTimestamp(x)
		if err != nil {
			return err
		} else if err := owner.monitor(math.Left(x), left, timestamp); err != nil {
			return err
		}
	}

	// If a stop condition has been reached, stop.
	ver := owner.state.greatestVersionAt(x)
	if owner.provider.StopCondition(x, ver) {
		return nil
	}

	// Obtain a search binary ladder from the current log entry where the target
	// version is the greatest version of the label expected to exist at this
	// point, based on the label owner's state.
	if ver < 0 {
		res, err := owner.provider.GetSearchBinaryLadder(x, 0, false)
		if err != nil {
			return err
		} else if res != -1 {
			return errors.New("binary ladder inconsistent with expected greatest version of label")
		}
	} else {
		res, err := owner.provider.GetSearchBinaryLadder(x, uint32(ver), false)
		if err != nil {
			return err
		} else if res != 0 {
			return errors.New("binary ladder inconsistent with expected greatest version of label")
		}
	}
	owner.state.setStarting(x)

	// If the current log entry has a right child, recurse to the right child.
	if noRightChild(x, owner.n) {
		return nil
	}
	timestamp, err := owner.provider.GetTimestamp(x)
	if err != nil {
		return err
	}
	return owner.monitor(math.Right(x, owner.n), timestamp, right)
}

// Monitor performs owner monitoring, ensuring that the label has not been
// modified without the label owner's permission.
//
// Algorithm from the second portion of Section 8.3.
func (owner *Owner) Monitor() error {
	if owner.state == nil {
		return errors.New("label owner state has not been initialized")
	}
	return owner.monitor(math.Root(owner.n), 0, owner.rightmost)
}

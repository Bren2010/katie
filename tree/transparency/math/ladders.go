package math

import (
	"errors"

	"github.com/Bren2010/katie/tree/prefix"
)

func baseBinaryLadder(n uint32) []uint32 {
	out := make([]uint32, 0)

	for {
		val := (uint32(1) << len(out)) - 1
		out = append(out, val)
		if val > n {
			break
		}
	}

	lowerBound, upperBound := out[len(out)-2], out[len(out)-1]
	for lowerBound+1 < upperBound {
		val := (lowerBound + upperBound) / 2
		out = append(out, val)
		if val <= n {
			lowerBound = val
		} else {
			upperBound = val
		}
	}

	return out
}

// SearchBinaryLadder returns the versions of a label to lookup for a search
// binary ladder.
//
// `t` is the target version of the label. `n` is the greatest version of the
// label in the current log entry. `leftInclusion` contains versions where an
// inclusion proof was already provided to the left. `rightNonInclusion`
// contains versions where a non-inclusion proof was already provided to the
// right.
func SearchBinaryLadder(
	t, n uint32,
	leftInclusion map[uint32]uint64,
	rightNonInclusion map[uint32]uint64,
) []uint32 {
	out := make([]uint32, 0)

	for _, v := range baseBinaryLadder(t) {
		// Lookup is duplicate in two scenarios:
		// - Inclusion proof for version was already provided to the left.
		// - Non-inclusion proof for version was already provided to the right.
		_, leftOk := leftInclusion[v]
		_, rightOk := rightNonInclusion[v]
		wouldBeDuplicate := leftOk || rightOk
		if !wouldBeDuplicate {
			out = append(out, v)
		}

		// Ladder ends early in two scenarios:
		// - Inclusion proof for version greater than to the target.
		// - Non-inclusion proof for version less than or equal to the target.
		wouldEnd := (v <= n && v > t) || (v > n && v <= t)
		if wouldEnd {
			break
		}
	}

	return out
}

// MonitoringBinaryLadder returns the versions of a label to lookup for a
// monitoring binary ladder.
//
// `t` is the target version of the label. `leftInclusion` contains versions
// where an inclusion proof was already provided to the left.
func MonitoringBinaryLadder(t uint32, leftInclusion map[uint32]uint64) []uint32 {
	out := make([]uint32, 0)

	for _, v := range baseBinaryLadder(t) {
		if _, ok := leftInclusion[v]; !ok && v <= t {
			out = append(out, v)
		}
	}

	return out
}

// InterpretSearchLadder takes as input the output of SearchBinaryLadder
// `ladder`, where the target version was `target`, and a PrefixProof `proof`
// corresponding to an execution of the search binary ladder.
//
// It returns -1 if the binary ladder indicates that greatest version of the
// label present is less than the target version, 0 if it is equal, and 1 if
// greater than the target.
func InterpretSearchLadder(ladder []uint32, target uint32, proof *prefix.PrefixProof) (int, error) {
	if len(proof.Results) > len(ladder) {
		return 0, errors.New("unexpected number of results in prefix proof")
	}

	for i, version := range ladder {
		if i >= len(proof.Results) {
			return 0, errors.New("unexpected number of results in prefix proof")
		}
		res := proof.Results[i]

		// Determine if this lookup is / should've been the last one in the
		// binary ladder.
		if res.Inclusion() && version > target {
			if len(proof.Results) != i+1 {
				return 0, errors.New("unexpected number of results in prefix proof")
			}
			return 1, nil
		} else if !res.Inclusion() && version <= target {
			if len(proof.Results) != i+1 {
				return 0, errors.New("unexpected number of results in prefix proof")
			}
			return -1, nil
		}
	}

	return 0, nil
}

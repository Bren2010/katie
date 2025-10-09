package math

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
	leftInclusion map[uint32]struct{},
	rightNonInclusion map[uint32]struct{},
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
func MonitoringBinaryLadder(t uint32, leftInclusion map[uint32]struct{}) []uint32 {
	out := make([]uint32, 0)

	for _, v := range baseBinaryLadder(t) {
		if _, ok := leftInclusion[v]; !ok && v <= t {
			out = append(out, v)
		}
	}

	return out
}

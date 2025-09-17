package math

func baseBinaryLadder(n uint64) []uint64 {
	out := make([]uint64, 0)

	for {
		val := (uint64(1) << len(out)) - 1
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

// FixedVersionBinaryLadder returns the versions of a label to lookup for a
// fixed-version binary ladder.
//
// t is the target version of the label. n is the greatest version of the label
// that exists. leftInclusion contains versions where an inclusion proof was
// already provided to the left. rightNonInclusion contains versions where a
// non-inclusion proof was already provided to the right.
func FixedVersionBinaryLadder(
	t, n uint64,
	leftInclusion map[uint64]struct{},
	rightNonInclusion map[uint64]struct{},
) []uint64 {
	out := make([]uint64, 0)

	for _, v := range baseBinaryLadder(n) {
		// Ladder ends early in two scenarios:
		// - Inclusion proof for version greater than or equal to the target.
		// - Non-inclusion proof for version less than or equal to the target.
		wouldEnd := (v <= n && v >= t) || (v > n && n <= t)

		// Lookup is duplicate in two scenarios:
		// - Inclusion proof for version was already provided to the left.
		// - Non-inclusion proof for version was already provided to the right.
		_, leftOk := leftInclusion[v]
		_, rightOk := rightNonInclusion[v]
		wouldBeDuplicate := leftOk || rightOk
		if !wouldBeDuplicate {
			out = append(out, v)
		}

		if wouldEnd {
			break
		}
	}

	return out
}

// MonitorBinaryLadder returns the versions of a label to lookup for a
// monitoring binary ladder.
//
// t is the target (monitored) version of the label. leftInclusion contains
// versions where an inclusion proof was already provided to the left.
func MonitorBinaryLadder(t uint64, leftInclusion map[uint64]struct{}) []uint64 {
	out := make([]uint64, 0)

	for _, v := range baseBinaryLadder(t) {
		if _, ok := leftInclusion[v]; !ok && v <= t {
			out = append(out, v)
		}
	}

	return out
}

// GreatestVersionBinaryLadder returns the versions of a label to lookup for a
// greatest-version binary ladder.
//
// t is the greatest version of the label globally. n is the greatest version of
// the label in the current log entry. distinguished is true if the current log
// entry is distinguished. leftInclusion contains versions where an inclusion
// proof was already provided to the left. rightNonInclusion contains versions
// where a non-inclusion proof was already provided to the right. sameEntry
// contains versions where a proof has already been provided from the same log
// entry in the same query response.
func GreatestVersionBinaryLadder(
	t, n uint64,
	distinguished bool,
	leftInclusion map[uint64]struct{},
	rightNonInclusion map[uint64]struct{},
	sameEntry map[uint64]struct{},
) []uint64 {
	out := make([]uint64, 0)

	for _, v := range baseBinaryLadder(t) {
		// Ladder ends early if a non-inclusion proof is produced for a version
		// less than or equal to t.
		wouldEnd := v > n && v <= t

		var wouldBeDuplicate bool
		if distinguished {
			// Lookup is duplicate only if the same lookup has already been
			// provided in the same query response.
			_, sameOk := sameEntry[v]
			wouldBeDuplicate = sameOk
		} else {
			// Lookup is duplicate in two scenarios:
			// - Inclusion proof for version was already provided to the left.
			// - Non-inclusion proof for version was already provided to the right.
			_, leftOk := leftInclusion[v]
			_, rightOk := rightNonInclusion[v]
			wouldBeDuplicate = leftOk || rightOk
		}
		if !wouldBeDuplicate {
			out = append(out, v)
		}

		if wouldEnd {
			break
		}
	}

	return out
}

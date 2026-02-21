package algorithms

import (
	"github.com/Bren2010/katie/tree/prefix"
	"github.com/Bren2010/katie/tree/transparency/math"
)

type posAndVersions struct {
	pos  uint64
	vers []uint32
}

type versionTracker struct {
	inclusion, nonInclusion []posAndVersions
}

func (vt *versionTracker) AddResults(x uint64, omit bool, ladder []uint32, results []prefix.PrefixSearchResult) {
	if !omit {
		return
	}

	var inclusion, nonInclusion []uint32
	for i, res := range results {
		if res.Inclusion() {
			inclusion = append(inclusion, ladder[i])
		} else {
			nonInclusion = append(nonInclusion, ladder[i])
		}
	}
	vt.inclusion = append(vt.inclusion, posAndVersions{pos: x, vers: inclusion})
	vt.nonInclusion = append(vt.nonInclusion, posAndVersions{pos: x, vers: nonInclusion})
}

func (vt *versionTracker) AddLadder(x uint64, omit bool, greatest int, ladder []uint32) {
	if !omit {
		return
	}

	var inclusion, nonInclusion []uint32
	for _, version := range ladder {
		if int(version) <= greatest {
			inclusion = append(inclusion, version)
		} else {
			nonInclusion = append(nonInclusion, version)
		}
	}
	vt.inclusion = append(vt.inclusion, posAndVersions{pos: x, vers: inclusion})
	vt.nonInclusion = append(vt.nonInclusion, posAndVersions{pos: x, vers: nonInclusion})
}

func (vt *versionTracker) SearchMaps(x uint64, omit bool) (leftInclusion, rightNonInclusion map[uint32]struct{}) {
	if !omit {
		return
	}

	leftInclusion = make(map[uint32]struct{})
	for _, entry := range vt.inclusion {
		if entry.pos < x {
			for _, ver := range entry.vers {
				leftInclusion[ver] = struct{}{}
			}
		}
	}
	rightNonInclusion = make(map[uint32]struct{})
	for _, entry := range vt.nonInclusion {
		if entry.pos > x {
			for _, ver := range entry.vers {
				rightNonInclusion[ver] = struct{}{}
			}
		}
	}
	return
}

func (vt *versionTracker) MonitoringMap(x uint64) (leftInclusion map[uint32]struct{}) {
	parents := make(map[uint64]struct{})
	for _, parent := range math.LeftDirectPath(x) {
		parents[parent] = struct{}{}
	}

	leftInclusion = make(map[uint32]struct{})
	for _, entry := range vt.inclusion {
		if _, ok := parents[entry.pos]; ok {
			for _, ver := range entry.vers {
				leftInclusion[ver] = struct{}{}
			}
		}
	}
	return
}

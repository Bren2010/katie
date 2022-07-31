package log

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strconv"

	"github.com/JumpPrivacy/katie/db"
	"github.com/JumpPrivacy/katie/tree/log/math"
)

// treeHash returns the intermediate hash of left and right.
func treeHash(left, right *nodeData) []byte {
	if err := left.validate(); err != nil {
		panic(err)
	} else if err := right.validate(); err != nil {
		panic(err)
	}

	input := append(left.marshal(), right.marshal()...)
	output := sha256.Sum256(input)
	return output[:]
}

// IncusionProof wraps all of the information necessary to verify a proof of
// inclusion for the log.
type InclusionProof struct {
	Hashes        [][]byte `json:"hashes"` // The copath hashes.
	Values        [][]byte `json:"values"` // The copath values.
	Intermediates [][]byte `json:"inter"`  // The intermediate node values.
}

// ConsistencyProof wraps a proof that one version of the log is an extension of
// a past version of the log.
type ConsistencyProof struct {
	Hashes        [][]byte `json:"hashes"` // Hashes along consistency path.
	Values        [][]byte `json:"values"` // Values along consistency path, for more recent revision.
	Intermediates [][]byte `json:"inter"`  // Intermediate values for computing more recent revision.
}

// Tree is an implementation of a Merkle tree where all new data is added to the
// right-most edge of the tree.
type Tree struct {
	tx db.KvStore
}

func NewTree(tx db.KvStore) *Tree {
	return &Tree{tx: tx}
}

// fetch loads the chunks for the requested nodes from the database. It returns
// an error if not all chunks are found.
func (t *Tree) fetch(n int, nodes []int) (*chunkSet, error) {
	dedup := make(map[int]struct{})
	for _, id := range nodes {
		dedup[math.Chunk(id)] = struct{}{}
	}
	strs := make([]string, 0, len(dedup))
	for id, _ := range dedup {
		strs = append(strs, strconv.Itoa(id))
	}

	data, err := t.tx.BatchGet(strs)
	if err != nil {
		return nil, err
	}
	for _, id := range strs {
		if _, ok := data[id]; !ok {
			return nil, fmt.Errorf("not all expected data was found in the database")
		}
	}

	// Parse chunk set.
	dataInt := make(map[int][]byte, len(data))
	for idStr, raw := range data {
		id, err := strconv.Atoi(idStr)
		if err != nil {
			return nil, err
		}
		dataInt[id] = raw
	}
	set, err := newChunkSet(n, dataInt)
	if err != nil {
		return nil, err
	}

	return set, nil
}

// fetchSpecific returns the values for the nodes given in `values` and the
// hashes for the nodes given in `hashes`, in that order.
func (t *Tree) fetchSpecific(n int, values, hashes []int) ([][]byte, [][]byte, error) {
	lookup := make([]int, len(values))
	copy(lookup, values) // Add the nodes that we need values for.

	// Add the nodes that we need to compute the requested hashes.
	rightEdge := make(map[int][]int)
	for _, id := range hashes {
		if math.IsFullSubtree(id, n) {
			lookup = append(lookup, id)
		} else {
			subtrees := math.FullSubtrees(id, n)
			rightEdge[id] = subtrees
			lookup = append(lookup, subtrees...)
		}
	}

	// Load everything from the database in one roundtrip.
	set, err := t.fetch(n, lookup)
	if err != nil {
		return nil, nil, nil, err
	}

	// Extract the values we want to return.
	rightValues := make(map[int][]byte)
	for i, id := range filteredParents(n - 1) {
		rightValues[id] = logs[n-1][i]
	}
	valuesOut := make([][]byte, len(values))
	for i, id := range values {
		if rightValue, ok := rightValues[id]; ok {
			valuesOut[i] = rightValue
		} else {
			valuesOut[i] = set.getValue(id)
		}
	}

	// Extract the hashes we want to return.
	hashesOut := make([][]byte, len(hashes))
	for i, id := range hashes {
		if subtrees, ok := rightEdge[id]; ok {
			// Manually calculate the intermediate.
			nd := set.get(subtrees[len(subtrees)-1])
			for i := len(subtrees) - 2; i >= 0; i-- {
				nd = &nodeData{
					leaf:  false,
					hash:  treeHash(set.get(subtrees[i]), nd),
					value: make([]byte, 32),
				}
			}
			hashesOut[i] = nd.hash
		} else {
			hashesOut[i] = set.get(id).hash
		}
	}

	return valuesOut, hashesOut, nil
}

// Get returns the value of log entry number `x` along with its proof of
// inclusion.
func (t *Tree) Get(x, n int) ([]byte, *InclusionProof, error) {
	if n == 0 {
		return nil, nil, fmt.Errorf("empty tree")
	} else if x >= n {
		return nil, nil, fmt.Errorf("can not get leaf beyond right edge of tree")
	}

	leaf := 2 * x
	cpath := math.Copath(leaf, n)
	dpath := math.DirectPath(leaf, n)
	if len(dpath) > 0 {
		dpath = dpath[:len(dpath)-1] // Remove root.
	}

	vids := append([]int{leaf}, append(cpath, dpath...)...)
	hids := noLeaves(cpath)
	values, hashes, _, err := t.fetchSpecific(n, vids, hids, -1)
	if err != nil {
		return nil, nil, err
	}

	return values[0], &InclusionProof{
		Hashes:        hashes,
		Values:        values[1 : 1+len(cpath)],
		Intermediates: values[1+len(cpath):],
	}, nil
}

// GetConsistencyProof returns a proof that the current log with n elements is
// an extension of a previous log root with m elements, 0 < m < n.
func (t *Tree) GetConsistencyProof(m, n int) (*ConsistencyProof, error) {
	if m <= 0 {
		return nil, fmt.Errorf("first parameter must be greater than zero")
	} else if m >= n {
		return nil, fmt.Errorf("second parameter must be greater than first")
	}

	ids := math.ConsistencyProof(m, n)

	// Build the set of intermediate nodes needed to compute root(n) by taking
	// the parent of each node in the consistency proof path, deduplicating, and
	// sorting by level (to match how the values will be used in verification).
	rootN := math.Root(n)
	parentsMap := make(map[int]struct{})
	for _, id := range ids {
		if p := math.Parent(id, n); p != rootN {
			if _, ok := parentsMap[p]; !ok {
				parentsMap[p] = struct{}{}
			}
		}
	}
	parents := make([]int, 0)
	for id, _ := range parentsMap {
		parents = append(parents, id)
	}
	sort.Sort(byLevel(parents))

	hids := noLeaves(ids)
	vids := append(ids, parents...)

	// Determine if we need to specifically fetch the value for root(m) because
	// m is a power of 2.
	rootM := math.Root(m)
	isFull := math.IsFullSubtree(rootM, m)

	logEntry := m - 1
	if isFull {
		logEntry = -1
		vids = append([]int{rootM}, vids...)
	}

	// Fetch everything from the database in one roundtrip.
	values, hashes, log, err := t.fetchSpecific(n, vids, hids, logEntry)
	if err != nil {
		return nil, err
	}

	// Clean up the IntermediatesM value.
	if isFull {
		log = [][]byte{values[0]}
		values = values[1:]
	} else if len(log) > 0 {
		log = log[:len(log)-1]
	}

	return &ConsistencyProof{
		Hashes:         hashes,
		Values:         values[:len(ids)],
		Intermediates:  values[len(ids):],
		IntermediatesM: log,
	}, nil
}

func (t *Tree) store(n int, data map[int][]byte, parents [][]byte) error {
	out := make(map[string][]byte, len(data))

	for id, raw := range data {
		out[strconv.Itoa(id)] = raw
	}

	rawParents := make([]byte, 0, 32*len(parents))
	for _, raw := range parents {
		rawParents = append(rawParents, raw...)
	}
	out["p"+strconv.Itoa(n)] = rawParents

	return t.tx.BatchPut(out)
}

// Append adds a new element to the end of the log and returns the new root
// value. n is the current value; after this operation is complete, methods to
// this class should be called with n+1.
func (t *Tree) Append(n int, value []byte, parents [][]byte) ([]byte, error) {
	if expected := len(Parents(n)); expected != len(parents) {
		return nil, fmt.Errorf("wrong number of parent node values given: wanted=%v, got=%v", expected, len(parents))
	} else if len(value) != 32 {
		return nil, fmt.Errorf("value has wrong length: %v", len(value))
	}
	for _, val := range parents {
		if len(val) != 32 {
			return nil, fmt.Errorf("parent value has wrong length: %v", len(val))
		}
	}

	// Calculate the set of nodes that we'll need to update / create.
	leaf := 2 * n
	path := make([]int, 1)
	path[0] = leaf
	for _, id := range math.DirectPath(leaf, n+1) {
		path = append(path, id)
	}

	alreadyExists := make(map[int]struct{})
	if n > 0 {
		alreadyExists[math.Chunk(leaf-2)] = struct{}{}
		for _, id := range math.DirectPath(leaf-2, n) {
			alreadyExists[math.Chunk(id)] = struct{}{}
		}
	}

	updateChunks := make([]int, 0) // These are dedup'ed by fetch.
	createChunks := make(map[int]struct{})
	for _, id := range path {
		id = math.Chunk(id)
		if _, ok := alreadyExists[id]; ok {
			updateChunks = append(updateChunks, id)
		} else {
			createChunks[id] = struct{}{}
		}
	}

	// Fetch the chunks we'll need to update along with nodes we'll need to know
	// to compute the new root or updated intermediates.
	set, _, err := t.fetch(n+1, append(updateChunks, math.Copath(leaf, n+1)...), nil)
	if err != nil {
		return nil, err
	}

	// Add any new chunks to the set and set the correct hashes everywhere.
	for id, _ := range createChunks {
		set.add(id)
	}

	set.set(leaf, nil, value)
	for i := 1; i < len(path); i++ {
		x := path[i]
		l, r := math.Left(x), math.Right(x, n+1)

		if math.Level(x)%4 == 0 {
			intermediate := treeHash(set.get(l), set.get(r))
			set.set(x, intermediate, parents[i-1])
		} else {
			set.set(x, nil, parents[i-1])
		}
	}

	// Calculate filtered list of parent values for the log entry.
	filteredParents := make([][]byte, 0)
	for i, val := range parents {
		if !math.IsFullSubtree(path[i+1], n+1) {
			filteredParents = append(filteredParents, val)
		}
	}

	// Commit to database and return new root.
	if err := t.store(n, set.marshal(), filteredParents); err != nil {
		return nil, err
	} else if n == 0 {
		return value, nil
	}
	return set.get(math.Root(n + 1)).hash, nil
}

func fullParents(n int) []int {
	out := make([]int, 0)
	for _, x := range math.DirectPath(2*n, n+1) {
		if math.IsFullSubtree(x, n+1) {
			out = append(out, x)
		}
	}
	return out
}

// Parents returns a slice containing the height of each parent of the n-th
// element added to a log.
//
// This information helps applications decide what additional data to store in
// the parent nodes of the next Append operation.
func Parents(n int) []int {
	out := make([]int, 0)
	for _, x := range fullParents(n) {
		out = append(out, math.Level(x))
	}
	return out
}

// filteredParents returns the entries from `Parents` that correspond to
// non-full subtrees.
func filteredParents(n int) []int {
	path := math.DirectPath(2*n, n+1)

	out := make([]int, 0)
	for _, id := range path {
		if !math.IsFullSubtree(id, n+1) {
			out = append(out, id)
		}
	}
	return out
}

// noLeaves returns `input` with all leaf nodes removed.
func noLeaves(input []int) (output []int) {
	for _, id := range input {
		if !math.IsLeaf(id) {
			output = append(output, id)
		}
	}
	return
}

// byLevel implements sort.Interface on a slice of node ids, sorting by level.
type byLevel []int

func (bl byLevel) Len() int           { return len(bl) }
func (bl byLevel) Less(i, j int) bool { return math.Level(bl[i]) < math.Level(bl[j]) }
func (bl byLevel) Swap(i, j int)      { bl[i], bl[j] = bl[j], bl[i] }

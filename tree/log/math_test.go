package log

import (
	"testing"
)

func assert(ok bool) {
	if !ok {
		panic("Assertion failed.")
	}
}

func slicesEq(left, right []int) bool {
	if len(left) != len(right) {
		return false
	}
	for i := 0; i < len(left); i++ {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func TestMath(t *testing.T) {
	assert(log2(0) == 0)
	assert(log2(8) == 3)
	assert(log2(10000) == 13)

	assert(level(1) == 1)
	assert(level(2) == 0)
	assert(level(3) == 2)

	assert(root(5) == 7)
	assert(left(7) == 3)
	assert(right(7, 8) == 11)

	assert(parent(1, 4) == 3)
	assert(parent(5, 4) == 3)

	assert(sibling(13, 8) == 9)
	assert(sibling(9, 8) == 13)

	assert(slicesEq(directPath(4, 8), []int{5, 3, 7}))
	assert(slicesEq(copath(4, 8), []int{6, 1, 11}))

	assert(slicesEq(fullSubtrees(7, 6), []int{3, 9}))
}

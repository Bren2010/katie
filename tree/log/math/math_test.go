package math

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
	assert(Log2(0) == 0)
	assert(Log2(8) == 3)
	assert(Log2(10000) == 13)

	assert(Level(1) == 1)
	assert(Level(2) == 0)
	assert(Level(3) == 2)

	assert(Root(5) == 7)
	assert(Left(7) == 3)
	assert(Right(7, 8) == 11)

	assert(Parent(1, 4) == 3)
	assert(Parent(5, 4) == 3)

	assert(Sibling(13, 8) == 9)
	assert(Sibling(9, 8) == 13)

	assert(slicesEq(DirectPath(4, 8), []int{5, 3, 7}))
	assert(slicesEq(Copath(4, 8), []int{6, 1, 11}))

	assert(slicesEq(FullSubtrees(7, 6), []int{3, 9}))
}

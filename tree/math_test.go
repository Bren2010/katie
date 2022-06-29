package tree

import (
	"testing"
)

func assert(ok bool) {
	if !ok {
		panic("Assertion failed.")
	}
}

func TestMath(t *testing.T) {
	assert(log2(0) == 0)
	assert(log2(8) == 3)
	assert(log2(10000) == 13)

	assert(level(1) == 1)
	assert(level(2) == 0)
	assert(level(3) == 2)
}

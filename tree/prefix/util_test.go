package prefix

import (
	"testing"

	"bytes"
)

var (
	testKey1 = []byte{
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
	}
	testKey2 = []byte{
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		16, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
	}
	testKey3 = []byte{
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		1, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
	}
)

func assert(ok bool) {
	if !ok {
		panic("assertion failed")
	}
}

func TestBuildKey(t *testing.T) {
	assert(bytes.Equal(
		testKey1,
		buildKey(testKey2[0:17], 1, testKey2[17:], true),
	))
	assert(bytes.Equal(
		testKey1,
		buildKey(testKey3[0:16], 1, testKey3[16:], false),
	))
}

func TestBuildPrefix(t *testing.T) {
	prefix1, _ := buildPrefix(testKey2[:16], 1, false)
	assert(bytes.Equal(testKey2[:17], prefix1))

	prefix2, _ := buildPrefix(testKey2[:17], 1, true)
	assert(bytes.Equal(testKey1[:17], prefix2))
}

func TestBuildSuffix(t *testing.T) {
	suffix1 := buildSuffix(testKey1, 16, true)
	assert(bytes.Equal(testKey1[16:], suffix1))

	suffix2 := buildSuffix(testKey1, 16, false)
	assert(bytes.Equal(testKey3[16:], suffix2))
}

// Package prefix implements a Prefix Tree.
package prefix

func getBit(data [32]byte, bit int) bool {
	return (data[bit/8]>>(7-(bit%8)))&1 == 1
}

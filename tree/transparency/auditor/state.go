package auditor

import "github.com/Bren2010/katie/tree/transparency/structs"

type AuditorState struct {
	TreeHead     *structs.AuditorTreeHead
	FullSubtrees [][]byte
	Timestamps   []uint64
	PrefixRoot   []byte
}

func (as *AuditorState) AddedSince(x uint64, vrfOutput []byte) bool {
	if as == nil {
		return true
	}
	panic("not implemented")
}

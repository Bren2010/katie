package auditor

import (
	"bytes"

	"github.com/Bren2010/katie/tree/transparency/structs"
)

type AuditorState struct {
	TreeHead     structs.AuditorTreeHead
	FullSubtrees [][]byte
	Timestamps   []uint64
	PrefixTree   []byte
}

func NewAuditorState(raw *bytes.Buffer) (*AuditorState, error) {
	panic("not implemented")
}

func (as *AuditorState) Marshal() ([]byte, error) {
	panic("not implemented")
}

func (as *AuditorState) AddedSince(x uint64, vrfOutput []byte) bool {
	if as == nil {
		return true
	}
	panic("not implemented")
}

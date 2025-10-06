package transparency

import (
	"github.com/Bren2010/katie/db"
	"github.com/Bren2010/katie/tree/transparency/structs"
)

// Tree is an implementation of a Transparency Tree that handles all state
// management, the evaluation of a VRF, and generating/opening commitments.
type Tree struct {
	config structs.PrivateConfig
	tx     db.TransparencyStore

	latest *db.TransparencyTreeRoot
}

func NewTree(config structs.PrivateConfig, tx db.TransparencyStore) (*Tree, error) {
	latest, err := tx.GetRoot()
	if err != nil {
		return nil, err
	}
	return &Tree{
		config: config,
		tx:     tx,

		latest: latest,
	}, nil
}

func (t *Tree) FixedVersionSearch(label []byte, ver uint32) {

}

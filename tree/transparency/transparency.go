package transparency

import (
	"bytes"
	"errors"

	"github.com/Bren2010/katie/db"
	"github.com/Bren2010/katie/tree/transparency/structs"
)

// Tree is an implementation of a Transparency Tree that handles all state
// management, the evaluation of a VRF, and generating/opening commitments.
type Tree struct {
	config      structs.PrivateConfig
	tx          db.TransparencyStore
	treeHead    *structs.TreeHead
	auditorHead *structs.AuditorTreeHead
}

func NewTree(config structs.PrivateConfig, tx db.TransparencyStore) (*Tree, error) {
	rawTreeHead, rawAuditor, err := tx.GetTreeHead()
	if err != nil {
		return nil, err
	}

	var (
		treeHead    *structs.TreeHead
		auditorHead *structs.AuditorTreeHead
	)
	if rawTreeHead != nil {
		treeHead, err = structs.NewTreeHead(bytes.NewBuffer(rawTreeHead))
		if err != nil {
			return nil, err
		}
	}
	if config.Mode == structs.ThirdPartyAuditing && rawAuditor != nil {
		auditorHead, err = structs.NewAuditorTreeHead(bytes.NewBuffer(rawAuditor))
		if err != nil {
			return nil, err
		}
	}

	return &Tree{
		config:      config,
		tx:          tx,
		treeHead:    treeHead,
		auditorHead: auditorHead,
	}, nil
}

func (t *Tree) fullTreeHead(last *uint64) (*structs.FullTreeHead, error) {
	if last != nil {
		if *last == t.treeHead.TreeSize {
			return &structs.FullTreeHead{}, nil
		} else if *last > t.treeHead.TreeSize {
			return nil, errors.New("tree size advertised by user is greater than current tree size")
		}
	}
	return &structs.FullTreeHead{TreeHead: t.treeHead, AuditorTreeHead: t.auditorHead}, nil
}

func (t *Tree) Search(req *structs.SearchRequest) (*structs.SearchResponse, error) {
	fth, err := t.fullTreeHead(req.Last)
	if err != nil {
		return nil, err
	}
	// ...
}

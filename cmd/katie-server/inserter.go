package main

import (
	"github.com/JumpPrivacy/katie/db"
	"github.com/JumpPrivacy/katie/tree/transparency"
)

type InsertRequest struct {
	Key   string
	Value []byte
	Resp  chan<- InsertResponse
}

type InsertResponse struct {
	Root *db.TransparencyTreeRoot
	Err  error
}

// inserter is a goroutine that receives insertion requests over `ch`, adds the
// requested data to the tree, and responds with the new tree root.
func inserter(tree *transparency.Tree, ch chan InsertRequest) {
	for {
		req := <-ch
		root, err := tree.Insert(req.Key, req.Value)
		req.Resp <- InsertResponse{root, err}
	}
	// TODO: Restart thread in case of panic.
}

package main

import (
	"fmt"
	"time"

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

		start := time.Now()
		root, err := tree.Insert(req.Key, req.Value)
		insertOps.WithLabelValues(fmt.Sprint(err == nil)).Inc()
		insertDur.Observe(float64(time.Since(start).Microseconds()))

		select {
		case req.Resp <- InsertResponse{root, err}:
		default:
		}
	}
	// TODO: Restart thread in case of panic.
}

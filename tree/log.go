package tree

import (
	"github.com/JumpPrivacy/katie/db"
)

// LogTree is an implementation of a Merkle tree where the leaves are the only
// nodes that store data and all new data is added to the right-most edge of the
// tree.
type LogTree struct {
	conn db.Conn
}

func NewLogTree(conn db.Conn) *LogTree {
	return &LogTree{conn: conn}
}

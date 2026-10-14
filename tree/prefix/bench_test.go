package prefix

import (
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"testing"

	"github.com/Bren2010/katie/crypto/suites"
	"github.com/Bren2010/katie/db"
)

var (
	benchInitialEntries = flag.Uint64("prefix.entries", 1_000_000, "number of entries to pre-populate the prefix tree with before benchmarking")
	benchInitialBatch   = flag.Uint64("prefix.initbatch", 50_000, "batch size used while pre-populating the prefix tree")
	benchDBPath         = flag.String("prefix.dbpath", "", "directory to keep the database in (and reuse across runs); a temporary directory is used if empty")
	benchCacheSize      = flag.Int64("prefix.cachesize", 1<<32, "size of the database block cache in bytes")
)

// kvTree wraps a prefix tree backed by an on-disk key-value store, tracking the
// current version. The current version is stored in the database as the tree
// head so that a pre-populated database can be reused across benchmark runs.
type kvTree struct {
	cs      suites.CipherSuite
	kv      db.KeyValueStore
	ver     uint64
	entries uint64
}

func openKVTree(b *testing.B, kv db.KeyValueStore) *kvTree {
	t := &kvTree{cs: suites.KTSha256P256{}, kv: kv}

	head, _, err := db.NewTransparencyStore(context.Background(), kv, true).GetTreeHead()
	if err != nil {
		b.Fatal(err)
	} else if head != nil {
		if len(head) != 16 {
			b.Fatal("unexpected tree head format in existing database")
		}
		t.ver = binary.BigEndian.Uint64(head[:8])
		t.entries = binary.BigEndian.Uint64(head[8:])
	}
	return t
}

// mutate applies a single batch of insertions and commits it to the database.
func (t *kvTree) mutate(b *testing.B, add []Entry) {
	ts := db.NewTransparencyStore(context.Background(), t.kv, false)
	_, err := NewTree(t.cs, ts.PrefixStore()).Mutate(t.ver, add, nil)
	if err != nil {
		b.Fatal(err)
	}
	t.ver++
	t.entries += uint64(len(add))

	head := make([]byte, 16)
	binary.BigEndian.PutUint64(head[:8], t.ver)
	binary.BigEndian.PutUint64(head[8:], uint64(t.entries))
	ts.PutTreeHead(head)
	if err := ts.Commit(); err != nil {
		b.Fatal(err)
	}
}

func randomEntries(n uint64) []Entry {
	entries := make([]Entry, n)
	for i := range entries {
		vrfOutput, commitment := randomBytes(), randomBytes()
		entries[i] = Entry{vrfOutput[:], commitment[:]}
	}
	sortEntries(entries)
	return entries
}

// BenchmarkPrefixTree measures the throughput of inserting new entries into a
// large prefix tree backed by an on-disk Pebble database, as a function of
// batch size. Each operation is one call to Mutate followed by a synced commit
// to the database. The reported "mods/s" metric is the number of entries
// inserted per second.
//
// The tree is pre-populated with -prefix.entries entries (default 1M) before
// any measurement. Use -prefix.dbpath to keep the populated databases between
// runs, since populating them is slow. Each sub-benchmark adds entries to the
// tree, so it grows slightly over the course of the benchmark.
func BenchmarkPrefixTree(b *testing.B) {
	path := *benchDBPath
	if path == "" {
		path = b.TempDir()
	}

	kv, err := db.NewPDBKeyValueStore(path, *benchCacheSize)
	if err != nil {
		b.Fatal(err)
	}
	t := openKVTree(b, kv)

	if t.entries < *benchInitialEntries {
		b.Logf("populating tree from %d to %d entries", t.entries, *benchInitialEntries)
		for t.entries < *benchInitialEntries {
			t.mutate(b, randomEntries(min(*benchInitialBatch, *benchInitialEntries-t.entries)))
		}
	}
	b.Logf("tree has %d entries at version %d", t.entries, t.ver)

	for _, batchSize := range []uint64{1, 10, 100, 1000, 10000} {
		b.Run(fmt.Sprintf("batch=%d", batchSize), func(b *testing.B) {
			batches := make([][]Entry, b.N)
			for i := range batches {
				batches[i] = randomEntries(batchSize)
			}

			b.ResetTimer()
			for i := range b.N {
				t.mutate(b, batches[i])
			}
			b.StopTimer()

			b.ReportMetric(float64(b.N)*float64(batchSize)/b.Elapsed().Seconds(), "mods/s")
		})
	}
}

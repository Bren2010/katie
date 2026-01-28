package transparency

import (
	"testing"

	"github.com/Bren2010/katie/crypto/suites"
	"github.com/Bren2010/katie/tree/transparency/structs"
)

func TestTimestampsMonotonic(t *testing.T) {
	cs := suites.KTSha256P256{}
	handler := newReceivedProofHandler(cs, structs.CombinedTreeProof{
		Timestamps: []uint64{0, 1, 2},
	})
	provider := newDataProvider(cs, handler)

	if ts, err := provider.GetTimestamp(1000); ts != 0 || err != nil {
		t.Fatalf("unexpected result: %v, %v", ts, err)
	} else if ts, err := provider.GetTimestamp(2000); ts != 1 || err != nil {
		t.Fatalf("unexpected result: %v, %v", ts, err)
	} else if ts, err := provider.GetTimestamp(1000); ts != 0 || err != nil {
		t.Fatalf("unexpected result: %v, %v", ts, err)
	} else if _, err := provider.GetTimestamp(1500); err.Error() != "timestamps are not monotonic" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTimestampsRetained(t *testing.T) {
	cs := suites.KTSha256P256{}
	handler := newReceivedProofHandler(cs, structs.CombinedTreeProof{
		Timestamps: []uint64{0, 2},
	})
	provider := newDataProvider(cs, handler)

	provider.AddRetained(nil, map[uint64]structs.LogEntry{2000: {Timestamp: 1}})

	if ts, err := provider.GetTimestamp(1000); ts != 0 || err != nil {
		t.Fatalf("unexpected result: %v, %v", ts, err)
	} else if ts, err := provider.GetTimestamp(2000); ts != 1 || err != nil {
		t.Fatalf("unexpected result: %v, %v", ts, err)
	} else if ts, err := provider.GetTimestamp(3000); ts != 2 || err != nil {
		t.Fatalf("unexpected result: %v, %v", ts, err)
	}
}

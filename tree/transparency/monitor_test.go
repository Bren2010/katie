package transparency

import (
	"testing"

	"github.com/Bren2010/katie/tree/transparency/structs"
)

func verifyContactMonitorResponse(
	t *testing.T,
	res *structs.ContactMonitorResponse,
	expected int,
) {
	if res.FullTreeHead.TreeHead == nil {
		t.Fatal("tree head not provided")
	} else if len(res.Monitor.PrefixProofs) != expected {
		t.Fatal("unexpected number of prefix proofs provided")
	}
}

func TestContactMonitor(t *testing.T) {
	tree, labels := generateRandomTree(t)

	// Verify no position is duplicate.
	entries := []structs.MonitorMapEntry{{Position: 1, Version: 0}, {Position: 1, Version: 1}}
	_, err := tree.ContactMonitor(&structs.ContactMonitorRequest{Label: labels[0], Entries: entries})
	if err.Error() != "monitoring map is not sorted by position" {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify no version is duplicate.
	entries = []structs.MonitorMapEntry{{Position: 0, Version: 0}, {Position: 1, Version: 0}}
	_, err = tree.ContactMonitor(&structs.ContactMonitorRequest{Label: labels[0], Entries: entries})
	if err.Error() != "monitoring map is not sorted by version" {
		t.Fatalf("unexpected error: %v", err)
	}

	// Rejects versions greater than expected.
	entries = []structs.MonitorMapEntry{{Position: 0, Version: 700}}
	_, err = tree.ContactMonitor(&structs.ContactMonitorRequest{Label: labels[0], Entries: entries})
	if err.Error() != "unexpected version found in monitoring map" {
		t.Fatalf("unexpected error: %v", err)
	}

	// Rejects positions that aren't on the version's direct path.
	entries = []structs.MonitorMapEntry{{Position: 2, Version: 0}}
	_, err = tree.ContactMonitor(&structs.ContactMonitorRequest{Label: labels[0], Entries: entries})
	if err.Error() != "unexpected position found in monitoring map" {
		t.Fatalf("unexpected error: %v", err)
	}

	// Accepts empty monitoring map.
	res, err := tree.ContactMonitor(&structs.ContactMonitorRequest{Label: labels[0], Entries: nil})
	if err != nil {
		t.Fatal(err)
	}
	verifyContactMonitorResponse(t, res, 0)

	// Accepts monitoring map with one entry where position is equal to where
	// version was inserted.
	entries = []structs.MonitorMapEntry{{Position: 2, Version: 2}}
	res, err = tree.ContactMonitor(&structs.ContactMonitorRequest{Label: labels[0], Entries: entries})
	if err != nil {
		t.Fatal(err)
	}
	verifyContactMonitorResponse(t, res, 1)

	// Accepts monitoring map with one entry where position is on right direct
	// path of where version was inserted.
	entries = []structs.MonitorMapEntry{{Position: 1, Version: 0}}
	res, err = tree.ContactMonitor(&structs.ContactMonitorRequest{Label: labels[0], Entries: entries})
	if err != nil {
		t.Fatal(err)
	}
	verifyContactMonitorResponse(t, res, 0)

	// Accepts monitoring map with multiple entries.
	entries = []structs.MonitorMapEntry{{Position: 2, Version: 2}, {Position: 4, Version: 4}}
	res, err = tree.ContactMonitor(&structs.ContactMonitorRequest{Label: labels[0], Entries: entries})
	if err != nil {
		t.Fatal(err)
	}
	verifyContactMonitorResponse(t, res, 2)
}

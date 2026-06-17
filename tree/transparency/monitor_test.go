package transparency

import (
	"slices"
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

	// Rejects positions that are greater than tree size.
	entries = []structs.MonitorMapEntry{{Position: 200, Version: 0}}
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

func verifyOwnerInitResponse(
	t *testing.T,
	res *structs.OwnerInitResponse,
	greatestVers []uint32,
) {
	if res.FullTreeHead.TreeHead == nil {
		t.Fatal("tree head not provided")
	} else if !slices.Equal(res.GreatestVersions, greatestVers) {
		t.Fatal("unexpected greatest versions provided")
	}

	ladder := allLadderVersions(greatestVers)
	if len(res.BinaryLadder) != len(ladder) {
		t.Fatal("unexpected number of binary ladder steps provided")
	}
	for i, ver := range ladder {
		commitmentExpected := ver <= greatestVers[len(greatestVers)-1]
		if commitmentExpected && res.BinaryLadder[i].Commitment == nil {
			t.Fatal("commitment not provided when expected")
		} else if !commitmentExpected && len(res.BinaryLadder[i].Commitment) > 0 {
			t.Fatal("commitment provided when not expected")
		}
	}

	if len(res.Init.PrefixProofs) != len(greatestVers) {
		t.Fatal("unexpected number of prefix proofs provided")
	}
}

func TestOwnerInit(t *testing.T) {
	tree, labels := generateRandomTree(t)

	// Rejects non-distinguished starting log entry.
	_, err := tree.OwnerInit(&structs.OwnerInitRequest{Label: labels[0], Start: 2})
	if err.Error() != "requested starting position is not distinguished" {
		t.Fatalf("unexpected error: %v", err)
	}

	// Rejects starting log entry greater than tree size.
	_, err = tree.OwnerInit(&structs.OwnerInitRequest{Label: labels[0], Start: 200})
	if err.Error() != "requested starting position is not distinguished" {
		t.Fatalf("unexpected error: %v", err)
	}

	// Accepts distinguished log entry 0, and restricts data provided to
	// versions that existed at that point.
	res, err := tree.OwnerInit(&structs.OwnerInitRequest{Label: labels[0], Start: 0})
	if err != nil {
		t.Fatal(err)
	}
	verifyOwnerInitResponse(t, res, []uint32{0})

	// Accepts distinguished log entry 3, and restricts data provided to
	// versions that existed at that point.
	res, err = tree.OwnerInit(&structs.OwnerInitRequest{Label: labels[0], Start: 3})
	if err != nil {
		t.Fatal(err)
	}
	verifyOwnerInitResponse(t, res, []uint32{3})
}

func TestOwnerMonitor(t *testing.T) {
	tree, labels := generateRandomTree(t)

	// Rejects `start` greater than tree size.
	_, err := tree.OwnerMonitor(&structs.OwnerMonitorRequest{Label: labels[0], Start: 200})
	if err.Error() != "advertised starting position is greater than tree size" {
		t.Fatalf("unexpected error: %v", err)
	}

	// Rejects `greatest_version` greater than greatest known version.
	ver := uint32(200)
	_, err = tree.OwnerMonitor(&structs.OwnerMonitorRequest{Label: labels[0], Start: 1, GreatestVersion: &ver})
	if err.Error() != "version advertised is greater than known greatest version" {
		t.Fatalf("unexpected error: %v", err)
	}

	// Rejects `greatest_version` less than greatest version at starting
	// position.
	ver = 0
	_, err = tree.OwnerMonitor(&structs.OwnerMonitorRequest{Label: labels[0], Start: 1, GreatestVersion: &ver})
	if err.Error() != "version advertised is less than version at starting position" {
		t.Fatalf("unexpected error: %v", err)
	}

	// Continues to rightmost distinguished log entry if possible.
	ver = 6
	res, err := tree.OwnerMonitor(&structs.OwnerMonitorRequest{Label: labels[0], Start: 0, GreatestVersion: &ver})
	if err != nil {
		t.Fatal(err)
	} else if len(res.Monitor.PrefixProofs) != 2 {
		t.Fatal("unexpected number of prefix proofs provided")
	}

	// Stops before reaching a log entry if the version it contains is greater
	// than the user knows about.
	ver = 1
	res, err = tree.OwnerMonitor(&structs.OwnerMonitorRequest{Label: labels[0], Start: 0, GreatestVersion: &ver})
	if err != nil {
		t.Fatal(err)
	} else if len(res.Monitor.PrefixProofs) != 1 {
		t.Fatal("unexpected number of prefix proofs provided")
	}

	// Distinguished log entry is omitted from contact monitoring if it's to the
	// right of the owner's starting position.
	ver = 6
	res, err = tree.OwnerMonitor(&structs.OwnerMonitorRequest{
		Label:           labels[0],
		Entries:         []structs.MonitorMapEntry{{Position: 2, Version: 2}},
		Start:           0,
		GreatestVersion: &ver,
	})
	if err != nil {
		t.Fatal(err)
	} else if len(res.Monitor.PrefixProofs) != 2 {
		t.Fatal("unexpected number of prefix proofs provided")
	}

	// Distinguished log entry is not omitted from contact monitoring if it's to
	// the left of the owner's starting position.
	res, err = tree.OwnerMonitor(&structs.OwnerMonitorRequest{
		Label:           labels[0],
		Entries:         []structs.MonitorMapEntry{{Position: 2, Version: 2}},
		Start:           6,
		GreatestVersion: &ver,
	})
	if err != nil {
		t.Fatal(err)
	} else if len(res.Monitor.PrefixProofs) != 1 {
		t.Fatal("unexpected number of prefix proofs provided")
	}
}

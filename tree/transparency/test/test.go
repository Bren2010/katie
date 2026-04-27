package test

import (
	"encoding/hex"
	"fmt"
	"slices"
	"testing"

	"github.com/Bren2010/katie/crypto/suites"
	"github.com/Bren2010/katie/tree/transparency/structs"
)

func Config(t *testing.T) structs.PrivateConfig {
	cs := suites.KTSha256P256{}

	rawSigKey, err := hex.DecodeString("d4987fdd18738be11e93f7f087bf3e0ef5743b8deea192509bbf716c9463c218")
	if err != nil {
		t.Fatal(err)
	}
	sigKey, err := cs.ParseSigningPrivateKey(rawSigKey)
	if err != nil {
		t.Fatal(err)
	}
	rawVrfKey, err := hex.DecodeString("d1f2dcc02cc82c1f2b623e91946c945a2a1eb2983a47f283d8dd2af3d9b9d9ad")
	if err != nil {
		t.Fatal(err)
	}
	vrfKey, err := cs.ParseVRFPrivateKey(rawVrfKey)
	if err != nil {
		t.Fatal(err)
	}

	return structs.PrivateConfig{
		SignatureKey: sigKey,
		VrfKey:       vrfKey,

		Config: structs.Config{
			Suite: cs,
			Mode:  structs.ContactMonitoring,

			MaxAhead:                   1000,
			MaxBehind:                  1000,
			ReasonableMonitoringWindow: 86400 * 1000,
			MaximumLifetime:            0,
		},
	}
}

func ConfigWithAuditor(t *testing.T) (structs.PrivateConfig, suites.SigningPrivateKey) {
	config := Config(t)

	rawAuditorKey, err := hex.DecodeString("ad8dc7973a514fbd609916b6b4a529387f33a586856e9ff6f4adcb12072ab8b2")
	if err != nil {
		t.Fatal(err)
	}
	auditorKey, err := config.Suite.ParseSigningPrivateKey(rawAuditorKey)
	if err != nil {
		t.Fatal(err)
	}

	config.Mode = structs.ThirdPartyAuditing
	config.MaxAuditorLag = 1
	config.AuditorStartPos = 0
	config.AuditorPublicKey = auditorKey.Public()

	return config, auditorKey
}

type ProofHandle struct {
	timestamps map[uint64]uint64
	versions   map[uint64]uint32

	requested         []uint64
	searchLadders     []uint64
	monitoringLadders []uint64
	inclusionProofs   []uint64

	stopPos uint64
}

func NewProofHandle(timestamps map[uint64]uint64, versions map[uint64]uint32) *ProofHandle {
	return &ProofHandle{timestamps: timestamps, versions: versions}
}

func (ph *ProofHandle) Verify(requested, searchLadders, monitoringLadders, inclusionProofs []uint64) error {
	if !slices.Equal(ph.requested, requested) {
		return fmt.Errorf("unexpected log entries requested: %v", ph.requested)
	} else if !slices.Equal(ph.searchLadders, searchLadders) {
		return fmt.Errorf("unexpected search ladders requested: %v", ph.searchLadders)
	} else if !slices.Equal(ph.monitoringLadders, monitoringLadders) {
		return fmt.Errorf("unexpected monitoring ladders requested: %v", ph.monitoringLadders)
	} else if !slices.Equal(ph.inclusionProofs, inclusionProofs) {
		return fmt.Errorf("unexpected inclusion proofs requested: %v", ph.inclusionProofs)
	}
	return nil
}

func (ph *ProofHandle) SetStopPos(x uint64) { ph.stopPos = x }

func (ph *ProofHandle) GetTimestamp(x uint64) (uint64, error) {
	ph.requested = append(ph.requested, x)

	ts, ok := ph.timestamps[x]
	if !ok {
		panic("timestamp not known for position")
	}
	return ts, nil
}

func (ph *ProofHandle) GetSearchBinaryLadder(x uint64, ver uint32, omit bool) ([]byte, int, error) {
	ph.searchLadders = append(ph.searchLadders, x)

	posVer, ok := ph.versions[x]
	if !ok {
		if ver == 0 && omit == false {
			return make([]byte, 32), -1, nil
		}
		panic("version not known for position")
	}

	if posVer < ver {
		return make([]byte, 32), -1, nil
	} else if posVer == ver {
		return make([]byte, 32), 0, nil
	} else {
		return make([]byte, 32), 1, nil
	}
}

func (ph *ProofHandle) GetMonitoringBinaryLadder(x uint64, ver uint32) ([]byte, error) {
	ph.monitoringLadders = append(ph.monitoringLadders, x)
	return make([]byte, 32), nil
}

func (ph *ProofHandle) GetInclusionProof(x uint64, ver uint32) ([]byte, error) {
	ph.inclusionProofs = append(ph.inclusionProofs, x)
	return make([]byte, 32), nil
}

func (ph *ProofHandle) StopCondition(x uint64, ver int) bool {
	return ph.stopPos == x
}

func (ph *ProofHandle) AddVersion(ver uint32, vrfOutput, commitment []byte) error {
	panic("not implemented")
}
func (ph *ProofHandle) GetPrefixTrees(xs []uint64) ([][]byte, error) {
	panic("not implemented")
}
func (ph *ProofHandle) Finish() ([][]byte, error) {
	panic("not implemented")
}
func (ph *ProofHandle) Output(leaves []uint64, n uint64, nP, m *uint64) (*structs.CombinedTreeProof, error) {
	panic("not implemented")
}

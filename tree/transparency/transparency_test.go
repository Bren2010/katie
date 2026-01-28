package transparency

import (
	"encoding/hex"
	"testing"

	"github.com/Bren2010/katie/crypto/suites"
	"github.com/Bren2010/katie/tree/transparency/structs"
)

func testConfig(t *testing.T) structs.PrivateConfig {
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

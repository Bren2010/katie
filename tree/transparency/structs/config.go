package structs

import (
	"bytes"

	"github.com/Bren2010/katie/crypto/suites"
	"github.com/Bren2010/katie/crypto/vrf"
)

type DeploymentMode byte

const (
	ContactMonitoring DeploymentMode = iota + 1
	ThirdPartyManagement
	ThirdPartyAuditing
)

type Config struct {
	Suite suites.CipherSuite
	Mode  DeploymentMode

	// Populated only when Mode is ThirdPartyManagement.
	LeafPublicKey suites.SigningPublicKey

	// Populated only when Mode is ThirdPartyAuditing.
	MaxAuditorLag    uint64
	AuditorStartPos  uint64
	AuditorPublicKey suites.SigningPublicKey

	MaxAhead                   uint64
	MaxBehind                  uint64
	ReasonableMonitoringWindow uint64
	MaximumLifetime            uint64 // Set to 0 if there is not one.
}

func (c *Config) IsExpired(ts, rightmost uint64) bool {
	if c.MaximumLifetime == 0 {
		return false
	}
	return rightmost-ts >= c.MaximumLifetime
}

func (c *Config) IsDistinguished(left, right uint64) bool {
	return right-left >= c.ReasonableMonitoringWindow
}

type PrivateConfig struct {
	SignatureKey suites.SigningPrivateKey
	VrfKey       vrf.PrivateKey
	Config
}

func (pc *PrivateConfig) Public() *PublicConfig {
	return &PublicConfig{
		SignatureKey: pc.SignatureKey.Public(),
		VrfKey:       pc.VrfKey.PublicKey(),
		Config:       pc.Config,
	}
}

type PublicConfig struct {
	SignatureKey suites.SigningPublicKey
	VrfKey       vrf.PublicKey
	Config
}

func (pc *PublicConfig) Marshal(buf *bytes.Buffer) error {
	writeNumeric(buf, pc.Suite.Id())
	writeNumeric(buf, uint8(pc.Mode))

	if err := writeBytes[uint16](buf, pc.SignatureKey.Bytes(), "signature public key"); err != nil {
		return err
	} else if err := writeBytes[uint16](buf, pc.VrfKey.Bytes(), "vrf public key"); err != nil {
		return err
	}

	switch pc.Mode {
	case ThirdPartyManagement:
		if err := writeBytes[uint16](buf, pc.LeafPublicKey.Bytes(), "leaf public key"); err != nil {
			return err
		}

	case ThirdPartyAuditing:
		writeNumeric(buf, pc.MaxAuditorLag)
		writeNumeric(buf, pc.AuditorStartPos)
		if err := writeBytes[uint16](buf, pc.AuditorPublicKey.Bytes(), "auditor public key"); err != nil {
			return err
		}
	}

	writeNumeric(buf, pc.MaxAhead)
	writeNumeric(buf, pc.MaxBehind)
	writeNumeric(buf, pc.ReasonableMonitoringWindow)
	if writeOptional(buf, pc.MaximumLifetime > 0) {
		writeNumeric(buf, pc.MaximumLifetime)
	}

	return nil
}

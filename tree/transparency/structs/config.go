package structs

import (
	"bytes"
	"encoding/binary"

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
	if err := binary.Write(buf, binary.BigEndian, pc.Suite.Id()); err != nil {
		return err
	} else if err := buf.WriteByte(byte(pc.Mode)); err != nil {
		return err
	} else if err := writeU16Bytes(buf, pc.SignatureKey.Bytes(), "signature public key"); err != nil {
		return err
	} else if err := writeU16Bytes(buf, pc.VrfKey.Bytes(), "vrf public key"); err != nil {
		return err
	}

	switch pc.Mode {
	case ThirdPartyManagement:
		if err := writeU16Bytes(buf, pc.LeafPublicKey.Bytes(), "leaf public key"); err != nil {
			return err
		}

	case ThirdPartyAuditing:
		if err := binary.Write(buf, binary.BigEndian, pc.MaxAuditorLag); err != nil {
			return err
		} else if err := binary.Write(buf, binary.BigEndian, pc.AuditorStartPos); err != nil {
			return err
		} else if err := writeU16Bytes(buf, pc.AuditorPublicKey.Bytes(), "auditor public key"); err != nil {
			return err
		}
	}

	if err := binary.Write(buf, binary.BigEndian, pc.MaxAhead); err != nil {
		return err
	} else if err := binary.Write(buf, binary.BigEndian, pc.MaxBehind); err != nil {
		return err
	} else if err := binary.Write(buf, binary.BigEndian, pc.ReasonableMonitoringWindow); err != nil {
		return err
	}
	if err := writeOptional(buf, pc.MaximumLifetime > 0); err != nil {
		return err
	} else if pc.MaximumLifetime > 0 {
		if err := binary.Write(buf, binary.BigEndian, pc.MaximumLifetime); err != nil {
			return err
		}
	}

	return nil
}

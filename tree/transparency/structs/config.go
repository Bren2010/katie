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

	// Recent is the application's definition of a "recent" distinguished log
	// entry, used when walking distinguished log entries. It is not part of
	// the serialized config, but must be the same for the Transparency Log and
	// its users. Walking distinguished log entries is not supported if nil.
	Recent RecentFunc
}

// RecentFunc returns whether a distinguished log entry meets the application's
// definition of "recent". `x` and `timestamp` are the position and timestamp of
// the log entry, `rightmost` is the timestamp of the rightmost log entry, and
// `count` is the number of recent distinguished log entries that have already
// been found, all of which are to the right of `x`.
//
// The definition must be monotonic: if a distinguished log entry is not
// recent, then no distinguished log entry to its left is recent either.
type RecentFunc func(x, timestamp, rightmost uint64, count int) bool

func (c *Config) IsExpired(ts, rightmost uint64) bool {
	if c.MaximumLifetime == 0 {
		return false
	}
	return rightmost-ts >= c.MaximumLifetime
}

func (c *Config) IsDistinguished(left, right uint64) bool {
	return right-left >= c.ReasonableMonitoringWindow
}

// DefaultMaxMonitoringProofs is the maximum number of prefix proofs included in
// a monitoring response when PrivateConfig.MaxMonitoringProofs is unset.
const DefaultMaxMonitoringProofs = 25

type PrivateConfig struct {
	SignatureKey suites.SigningPrivateKey
	VrfKey       vrf.PrivateKey
	Config

	// MaxMonitoringProofs is the maximum number of prefix proofs included in a
	// single monitoring response, after which owner monitoring is paginated.
	// It is a local setting and not part of the public config. Set to 0 to use
	// DefaultMaxMonitoringProofs.
	MaxMonitoringProofs int
}

// MonitoringProofLimit returns the maximum number of prefix proofs to include
// in a monitoring response.
func (pc *PrivateConfig) MonitoringProofLimit() int {
	if pc.MaxMonitoringProofs == 0 {
		return DefaultMaxMonitoringProofs
	}
	return pc.MaxMonitoringProofs
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

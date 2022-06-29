package main

import (
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io/ioutil"

	"github.com/JumpPrivacy/katie/crypto/vrf"
	"github.com/JumpPrivacy/katie/crypto/vrf/p256"

	"gopkg.in/yaml.v2"
)

// Config specifies the file format of config files.
type Config struct {
	ServerAddr string     `yaml:"addr"`
	TLSConfig  *TLSConfig `yaml:"tls"`
	tlsConfig  *tls.Config

	APIConfig *APIConfig `yaml:"api"`
}

// TLSConfig specifies the API server's TLS config. Since this is only intended
// for use with Cloudflare OriginCA, TLS on the server also starts requiring a
// valid client certificate.
type TLSConfig struct {
	Cert     string `yaml:"cert"`
	Key      string `yaml:"key"`
	ClientCA string `yaml:"client-ca"` // CA for validating client certificates.
}

type APIConfig struct {
	HomeRedirect string `yaml:"home"`

	SigningKey string `yaml:"signing-key"` // 32 byte hex-encoded seed for the signing private key.
	signingKey ed25519.PrivateKey

	VRFKey string `yaml:"vrf-key"` // PEM encoded VRF private key.
	vrfKey vrf.PrivateKey
}

func ReadConfig(filename string) (*Config, error) {
	// Read from file and parse.
	raw, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var parsed Config
	if err := yaml.Unmarshal(raw, &parsed); err != nil {
		return nil, err
	}

	// Check that all required fields are populated.
	if parsed.ServerAddr == "" {
		return nil, fmt.Errorf("field not provided: addr")
	} else if parsed.APIConfig == nil {
		return nil, fmt.Errorf("field not provided: api")
	} else if parsed.APIConfig.HomeRedirect == "" {
		return nil, fmt.Errorf("field not provided: api.home")
	} else if parsed.APIConfig.SigningKey == "" {
		return nil, fmt.Errorf("field not provided: api.signing-key")
	} else if parsed.APIConfig.VRFKey == "" {
		return nil, fmt.Errorf("field not provided: api.vrf-key")
	}

	// Parse TLS config if necessary.
	if parsed.TLSConfig != nil {
		cert, err := tls.LoadX509KeyPair(parsed.TLSConfig.Cert, parsed.TLSConfig.Key)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS certificate/key: %v", err)
		}

		certPool := x509.NewCertPool()
		caCerts, err := ioutil.ReadFile(parsed.TLSConfig.ClientCA)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS client CA: %v", err)
		} else if ok := certPool.AppendCertsFromPEM(caCerts); !ok {
			return nil, fmt.Errorf("no client CA certificates successfully parsed from file")
		}

		parsed.tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    certPool,
		}
	}

	// Parse cryptographic keys.
	seed, err := hex.DecodeString(parsed.APIConfig.SigningKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse signing key: %v", err)
	} else if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("signing key is wrong size: wanted=%v, got=%v", ed25519.SeedSize, len(seed))
	}
	parsed.APIConfig.signingKey = ed25519.NewKeyFromSeed(seed)

	parsed.APIConfig.vrfKey, err = p256.NewVRFSignerFromPEM([]byte(parsed.APIConfig.VRFKey))
	if err != nil {
		return nil, fmt.Errorf("failed to parse vrf key: %v", err)
	}

	return &parsed, nil
}

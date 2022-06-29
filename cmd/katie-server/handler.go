package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/json"
	"log"
	"net/http"
)

type Handler struct {
	config *APIConfig
}

// Home redirects requests to a pre-configured URL, like the API documentation.
func (h *Handler) Home(rw http.ResponseWriter, req *http.Request) {
	http.Redirect(rw, req, h.config.HomeRedirect, http.StatusSeeOther)
}

type MetaResponse struct {
	HashAlgorithm      string `json:"hash_algorithm"`
	SignatureAlgorithm string `json:"signature_algorithm"`
	VRFAlgorithm       string `json:"vrf_algorithm"`
	SigningKey         []byte `json:"signing_key"`
	VRFKey             []byte `json:"vrf_key"`
}

func (h *Handler) Meta(rw http.ResponseWriter, req *http.Request) {
	vrfPub := h.config.vrfKey.Public().(*ecdsa.PublicKey)
	res := MetaResponse{
		HashAlgorithm:      "sha256",
		SignatureAlgorithm: "ed25519",
		VRFAlgorithm:       "p256",
		SigningKey:         h.config.signingKey.Public().(ed25519.PublicKey),
		VRFKey:             elliptic.Marshal(vrfPub.Curve, vrfPub.X, vrfPub.Y),
	}
	if err := json.NewEncoder(rw).Encode(res); err != nil {
		log.Println(err)
	}
}

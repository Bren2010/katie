package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"

	"github.com/JumpPrivacy/katie/db"
	"github.com/JumpPrivacy/katie/tree/transparency"
	"github.com/gorilla/mux"
)

// ApiResponse wraps either response data or an error message with a "success"
// indicator boolean.
type ApiResponse struct {
	Success  bool        `json:"success"`
	Response interface{} `json:"response,omitempty"`
	Message  string      `json:"message,omitempty"`
}

// HttpError wraps an error that occurred while processing an HTTP request with
// the HTTP status code that should be returned.
type HttpError struct {
	Status int
	Err    error
}

// HandleAPI takes an API handler function as input and turns it into an
// http.HandlerFunc by adding error handling.
func HandleAPI(inner func(rw http.ResponseWriter, req *http.Request) *HttpError) http.HandlerFunc {
	return func(rw http.ResponseWriter, req *http.Request) {
		if err := inner(rw, req); err != nil {
			log.Printf("%v(%v): %v", req.URL.Path, err.Status, err.Err)

			rw.WriteHeader(err.Status)
			json.NewEncoder(rw).Encode(ApiResponse{
				Success: false,
				Message: err.Err.Error(),
			})
		}
	}
}

type Handler struct {
	config *APIConfig
	tx     db.TransparencyStore
	ch     chan<- InsertRequest
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

// Meta returns a JSON object with the log's configuration and public keys.
func (h *Handler) Meta(rw http.ResponseWriter, req *http.Request) *HttpError {
	if req.Method != "GET" {
		return &HttpError{http.StatusMethodNotAllowed, fmt.Errorf("method not allowed")}
	}
	vrfPub := h.config.vrfKey.Public().(*ecdsa.PublicKey)
	res := ApiResponse{
		Success: true,
		Response: MetaResponse{
			HashAlgorithm:      "sha256",
			SignatureAlgorithm: "ed25519",
			VRFAlgorithm:       "p256",
			SigningKey:         h.config.signingKey.Public().(ed25519.PublicKey),
			VRFKey:             elliptic.Marshal(vrfPub.Curve, vrfPub.X, vrfPub.Y),
		},
	}
	if err := json.NewEncoder(rw).Encode(res); err != nil {
		return &HttpError{http.StatusInternalServerError, err}
	}

	return nil
}

// Consistency returns a consistency proof between two versions of the log.
func (h *Handler) Consistency(rw http.ResponseWriter, req *http.Request) *HttpError {
	if req.Method != "GET" {
		return &HttpError{http.StatusMethodNotAllowed, fmt.Errorf("method not allowed")}
	}
	vars := mux.Vars(req)

	older, err := strconv.Atoi(vars["older"])
	if err != nil {
		return &HttpError{http.StatusBadRequest, fmt.Errorf("request path had unexpected format")}
	}
	newer, err := strconv.Atoi(vars["newer"])
	if err != nil {
		return &HttpError{http.StatusBadRequest, fmt.Errorf("request path had unexpected format")}
	}

	tree, err := transparency.NewTree(h.config.signingKey, h.config.vrfKey, h.tx)
	if err != nil {
		return &HttpError{http.StatusInternalServerError, err}
	}
	proof, err := tree.GetConsistency(older, newer)
	if err != nil {
		return &HttpError{http.StatusBadRequest, err}
	}
	res := ApiResponse{Success: true, Response: proof}
	if err := json.NewEncoder(rw).Encode(res); err != nil {
		return &HttpError{http.StatusInternalServerError, err}
	}

	return nil
}

package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Bren2010/katie/db"
	"github.com/Bren2010/katie/tree/transparency"
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

func extractPath(req *http.Request) string {
	full := req.URL.Path
	if len(full) > 0 && full[0] == '/' {
		full = full[1:]
	}
	parts := strings.Split(full, "/")
	if len(parts) == 0 {
		return "/"
	} else if len(parts) == 1 {
		return "/" + parts[0]
	}
	out := "/" + parts[0] + "/" + parts[1]
	if out == "/v1/account" && req.Method == "POST" {
		out = "POST:" + out
	}
	return out
}

// HandleAPI takes an API handler function as input and turns it into an
// http.HandlerFunc by adding error handling.
func HandleAPI(inner func(rw http.ResponseWriter, req *http.Request) *HttpError) http.HandlerFunc {
	return func(rw http.ResponseWriter, req *http.Request) {
		path := extractPath(req)

		if err := inner(rw, req); err != nil {
			requestCtr.WithLabelValues(path, fmt.Sprint(err.Status)).Inc()
			log.Printf("%v(%v): %v", req.URL.Path, err.Status, err.Err)

			rw.WriteHeader(err.Status)
			json.NewEncoder(rw).Encode(ApiResponse{
				Success: false,
				Message: err.Err.Error(),
			})
		} else {
			requestCtr.WithLabelValues(path, "200").Inc()
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

// Account handles both getting most recent account data over the GET method,
// and updating account data over the POST method.
func (h *Handler) Account(rw http.ResponseWriter, req *http.Request) *HttpError {
	// TOOD: Figure out some kind of authentication / domain-separation.
	if req.Method != "GET" && req.Method != "POST" {
		return &HttpError{http.StatusMethodNotAllowed, fmt.Errorf("method not allowed")}
	}
	vars := mux.Vars(req)
	account := vars["account"]

	last := -1
	if str, ok := vars["last"]; ok {
		parsed, err := strconv.Atoi(str)
		if err != nil {
			return &HttpError{http.StatusBadRequest, fmt.Errorf("request path had unexpected format")}
		}
		last = parsed
	}

	tree, err := transparency.NewTree(h.config.signingKey, h.config.vrfKey, h.tx)
	if err != nil {
		return &HttpError{http.StatusInternalServerError, err}
	}

	// If the request is over POST, read the request body and submit it to the
	// inserter goroutine to be added to the log.
	if req.Method == "POST" {
		value := make([]byte, 16*1024)

		n := 0
		for {
			m, err := req.Body.Read(value[n:])
			n += m
			if err == io.EOF {
				break
			} else if err != nil {
				return &HttpError{http.StatusInternalServerError, err}
			} else if n == len(value) {
				return &HttpError{http.StatusBadRequest, fmt.Errorf("request body is too large")}
			}
		}
		if n == 0 {
			return &HttpError{http.StatusBadRequest, fmt.Errorf("empty request body not allowed")}
		}

		resp := make(chan InsertResponse)
		timer := time.NewTimer(5 * time.Second)
		select {
		case h.ch <- InsertRequest{Key: account, Value: value[:n], Resp: resp}:
		case <-timer.C:
			return &HttpError{http.StatusInternalServerError, fmt.Errorf("submitting insertion request timed out")}
		}
		var root *db.TransparencyTreeRoot
		select {
		case res := <-resp:
			if res.Err != nil {
				return &HttpError{http.StatusInternalServerError, res.Err}
			}
			root = res.Root
		case <-timer.C:
			return &HttpError{http.StatusInternalServerError, fmt.Errorf("waiting for insertion result timed out")}
		}
		if !timer.Stop() {
			<-timer.C
		}

		tree.SetLatest(root)
	}

	// Search for the most recent version of account data.
	sr, err := tree.Search(account)
	if err != nil {
		return &HttpError{http.StatusInternalServerError, err}
	}
	if last != -1 {
		// Add a consistency proof if requested.
		sr.Consistency, err = tree.GetConsistency(last, int(sr.Root.TreeSize))
		if err != nil {
			return &HttpError{http.StatusInternalServerError, err}
		}
	}
	res := ApiResponse{Success: true, Response: sr}
	if err := json.NewEncoder(rw).Encode(res); err != nil {
		return &HttpError{http.StatusInternalServerError, err}
	}

	return nil
}

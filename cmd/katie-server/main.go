package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

var (
	configFile = flag.String("config", "", "Location of config file.")
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile | log.LUTC)
	flag.Parse()

	// Load config from disk.
	if *configFile == "" {
		log.Fatalf("No config file provided, see --help.")
	}
	config, err := ReadConfig(*configFile)
	if err != nil {
		log.Fatalf("Failed to load config file: %v", err)
	}

	// Setup handler for the API server.
	h := &Handler{
		config: config.APIConfig,
	}
	r := mux.NewRouter()
	r.HandleFunc("/", h.Home)

	// Setup the API server.
	srv := &http.Server{
		Addr:      config.ServerAddr,
		Handler:   r,
		TLSConfig: config.tlsConfig,
		// TODO: More config.
	}

	if config.TLSConfig == nil {
		log.Fatal(srv.ListenAndServe())
	} else {
		log.Fatal(srv.ListenAndServeTLS("", ""))
	}
}

type Handler struct {
	config *APIConfig
}

// Home redirects requests to a pre-configured URL, like the API documentation.
func (h *Handler) Home(rw http.ResponseWriter, req *http.Request) {
	fmt.Fprintln(rw, "Hello :)")
	// http.Redirect(rw, req, h.config.HomeRedirect, http.StatusSeeOther)
}

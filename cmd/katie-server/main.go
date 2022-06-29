// Command katie-server is the main server process that answers all client
// requests and sequences new changes to the log.
package main

import (
	"flag"
	"log"
	"net/http"
	"time"

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
	h := &Handler{config: config.APIConfig}
	r := mux.NewRouter()
	r.HandleFunc("/", h.Home)
	r.HandleFunc("/meta", h.Meta)

	// Setup the API server.
	srv := &http.Server{
		Addr:      config.ServerAddr,
		Handler:   r,
		TLSConfig: config.tlsConfig,

		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}

	log.Println("Starting API server.")
	if config.TLSConfig == nil {
		log.Fatal(srv.ListenAndServe())
	} else {
		log.Fatal(srv.ListenAndServeTLS("", ""))
	}
}

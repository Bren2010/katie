// Command katie-server is the main server process that answers all client
// requests and sequences new changes to the log.
package main

import (
	"flag"
	"log"
	"net/http"
	"time"

	"github.com/JumpPrivacy/katie/db"
	"github.com/JumpPrivacy/katie/tree/transparency"
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

	// Start the inserter thread.
	tx, err := db.NewLDBTransparencyStore(config.DatabaseFile)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	tree, err := transparency.NewTree(config.APIConfig.signingKey, config.APIConfig.vrfKey, tx)
	if err != nil {
		log.Fatalf("failed to initialize tree: %v", err)
	}
	ch := make(chan InsertRequest)

	go inserter(tree, ch)

	// Setup handler for the API server.
	h := &Handler{config: config.APIConfig, tx: tx.Clone(), ch: ch}
	r := mux.NewRouter()
	r.HandleFunc("/", h.Home)
	r.HandleFunc("/v1/meta", HandleAPI(h.Meta))
	r.HandleFunc("/v1/consistency/{older:[0-9]+}/{newer:[0-9]+}", HandleAPI(h.Consistency))
	r.HandleFunc("/v1/account/{account}", HandleAPI(h.Account))
	r.HandleFunc("/v1/account/{account}/{last:[0-9]+}", HandleAPI(h.Account))

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

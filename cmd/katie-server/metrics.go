//go:build ignore

package main

import (
	"fmt"
	"log"
	"net/http"
	"net/http/pprof"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	buildInfo = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "build_info",
			Help: "A metric with a constant '1' value labeled by version, and goversion.",
		},
		[]string{"version", "goversion"},
	)
	insertOps = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "insert_operations",
			Help: "Incremented for each insert operation, labeled by success or failure.",
		},
		[]string{"success"},
	)
	insertDur = prometheus.NewSummary(
		prometheus.SummaryOpts{
			Name: "insert_duration",
			Help: "Summary of how long an insert operation takes to complete.",
		},
	)
	requestCtr = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "requests",
			Help: "Incremented for each API request received.",
		},
		[]string{"path", "status"},
	)
)

func metrics(addr string) {
	buildInfo.WithLabelValues(Version, GoVersion).Set(1)
	prometheus.MustRegister(buildInfo)
	prometheus.MustRegister(insertOps)
	prometheus.MustRegister(insertDur)
	prometheus.MustRegister(requestCtr)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(rw http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/" {
			fmt.Fprintln(rw, "Hi, I'm a katie metrics and debugging server!")
		} else {
			rw.WriteHeader(404)
			fmt.Fprintln(rw, "404 not found")
		}
	})
	mux.Handle("/metrics", promhttp.Handler())

	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	mux.HandleFunc("/debug/version", func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(w, "Version: %s, GoVersion: %s", Version, GoVersion)
	})

	srv := &http.Server{
		Addr:    addr,
		Handler: mux,
	}
	log.Printf("Starting metrics server at: %v", addr)
	log.Fatal(srv.ListenAndServe())
}

package server

import (
	"embed"
	"encoding/json"
	"io/fs"
	"net/http"

	"github.com/tedsluis/nmap/internal/model"
)

//go:embed web/*
var webFS embed.FS

func ListenAndServe(addr string, topo *model.Topology) error {
	staticFS, err := fs.Sub(webFS, "web")
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/topology", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(topo)
	})
	mux.Handle("/", http.FileServer(http.FS(staticFS)))
	return http.ListenAndServe(addr, mux)
}

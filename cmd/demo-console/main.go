// Command demo-console is a local web UI that SSHes to the GhostCatcher victim
// lab and runs kill-chain stages one-by-one, showing human-readable ES evidence.
//
//	export GC_DEMO_SSH=root@137.184.103.63
//	export GC_DEMO_SSH_KEY=~/.ssh/id_ed25519
//	go run ./cmd/demo-console
//	open http://127.0.0.1:8090
package main

import (
	"embed"
	"encoding/json"
	"io/fs"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

//go:embed web/*
var webFS embed.FS

func main() {
	target := env("GC_DEMO_SSH", "root@137.184.103.63")
	key := env("GC_DEMO_SSH_KEY", "~/.ssh/id_ed25519")
	addr := env("GC_DEMO_LISTEN", "127.0.0.1:8090")

	ssh, err := dialSSH(target, key)
	if err != nil {
		log.Fatalf("ssh: %v", err)
	}
	defer ssh.Close()
	log.Printf("connected to %s", target)

	term := newTermHub()
	term.Printf("meta", "connected via SSH → %s", target)
	term.Printf("meta", "click a step — commands and remote output stream here")
	eng := newEngine(ssh, term, target)

	mux := http.NewServeMux()
	static, err := fs.Sub(webFS, "web")
	if err != nil {
		log.Fatal(err)
	}
	mux.Handle("/", http.FileServer(http.FS(static)))
	mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, eng.health())
	})
	mux.HandleFunc("GET /api/steps", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"target": target, "steps": eng.snapshot()})
	})
	mux.HandleFunc("GET /api/terminal", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"lines": term.Snapshot()})
	})
	mux.HandleFunc("GET /api/terminal/stream", term.serveSSE)
	mux.HandleFunc("POST /api/terminal/clear", func(w http.ResponseWriter, r *http.Request) {
		term.Clear()
		writeJSON(w, map[string]any{"ok": true})
	})
	mux.HandleFunc("POST /api/steps/{id}/run", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		st, err := eng.runStep(id)
		if err != nil && st.ID == "" {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		writeJSON(w, st)
	})
	mux.HandleFunc("POST /api/run-all", func(w http.ResponseWriter, r *http.Request) {
		// Default: kill-chain narrative only (safe for talks).
		order := []string{"reset", "webshell", "sudden_root", "persist", "reverse_shell"}
		if r.URL.Query().Get("scope") == "all" {
			order = nil
			for _, st := range eng.snapshot() {
				order = append(order, st.ID)
			}
		}
		var results []StepState
		for _, id := range order {
			st, err := eng.runStep(id)
			results = append(results, st)
			if err != nil && id != "reset" {
				writeJSON(w, map[string]any{"ok": false, "steps": results, "error": err.Error()})
				return
			}
		}
		writeJSON(w, map[string]any{"ok": true, "steps": results})
	})

	srv := &http.Server{
		Addr:              addr,
		Handler:           withLog(mux),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("demo console → http://%s", addr)
	log.Fatal(srv.ListenAndServe())
}

func withLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		if strings.HasPrefix(r.URL.Path, "/api/") {
			log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start).Round(time.Millisecond))
		}
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

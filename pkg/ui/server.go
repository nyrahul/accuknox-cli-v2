// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of KubeArmor

package ui

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/accuknox/accuknox-cli-v2/pkg/aibom"
	"github.com/accuknox/accuknox-cli-v2/pkg/cbom"
)

// Server is the knoxctl embedded web UI HTTP server.
type Server struct {
	addr    string
	version string
	mux     *http.ServeMux
}

// NewServer creates a new Server listening on addr (e.g. "0.0.0.0:10100").
func NewServer(addr, version string) *Server {
	s := &Server{addr: addr, version: version}
	s.mux = http.NewServeMux()
	s.registerRoutes()
	return s
}

// Start starts the HTTP server and opens the UI in the default browser.
func (s *Server) Start() error {
	url := "http://localhost:" + portFrom(s.addr)
	fmt.Printf("knoxctl UI  →  %s\n", url)
	fmt.Printf("Listening on %s  (Ctrl-C to stop)\n", s.addr)

	// Open browser after a short delay so the server is ready.
	go func() {
		time.Sleep(500 * time.Millisecond)
		openBrowser(url)
	}()

	srv := &http.Server{
		Addr:              s.addr,
		Handler:           s.mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	return srv.ListenAndServe()
}

// registerRoutes wires all HTTP handlers.
func (s *Server) registerRoutes() {
	// Static assets — serve the embedded SPA for every non-API route.
	sub, _ := fs.Sub(StaticFS, "static")
	fileServer := http.FileServer(http.FS(sub))
	s.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// All non-API paths fall through to index.html (SPA routing).
		if r.URL.Path != "/" {
			_, err := fs.Stat(sub, strings.TrimPrefix(r.URL.Path, "/"))
			if err != nil {
				r.URL.Path = "/"
			}
		}
		fileServer.ServeHTTP(w, r)
	})

	// API — version
	s.mux.HandleFunc("/api/version", cors(s.handleVersion))

	// API — CBOM
	s.mux.HandleFunc("/api/cbom/source", cors(s.handleCBOMSource))
	s.mux.HandleFunc("/api/cbom/image", cors(s.handleCBOMImage))

	// API — AIBOM
	s.mux.HandleFunc("/api/aibom/generate", cors(s.handleAIBOM))

	// API — generic CLI runner (image-scan, probe, vm, sbom)
	s.mux.HandleFunc("/api/run", cors(s.handleRun))
}

// ──────────────────────────────────────────────────────────────────────────────
// Handlers
// ──────────────────────────────────────────────────────────────────────────────

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]string{
		"version": s.version,
		"time":    time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *Server) handleCBOMSource(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Path        string `json:"path"`
		Name        string `json:"name"`
		Group       string `json:"group"`
		Version     string `json:"version"`
		Description string `json:"description"`
		License     string `json:"license"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, "invalid request: "+err.Error())
		return
	}
	if req.Path == "" {
		req.Path = "."
	}

	send, flush, ok := sseInit(w)
	if !ok {
		return
	}

	send("progress", progress(10, "Initialising source scanner…"))
	flush()

	opts := &cbom.Options{
		Path:        req.Path,
		Name:        req.Name,
		Group:       req.Group,
		Version:     req.Version,
		Description: req.Description,
		License:     req.License,
		Format:      "json",
	}

	send("progress", progress(30, "Scanning Go source files for cryptographic imports…"))
	flush()

	bom, err := cbom.GenerateFromSource(opts)
	if err != nil {
		send("error", errMsg(err))
		flush()
		return
	}

	send("progress", progress(80, "Building Cryptography BOM…"))
	flush()

	out, err := json.MarshalIndent(bom, "", "  ")
	if err != nil {
		send("error", errMsg(err))
		flush()
		return
	}

	count := cbom.ComponentCount(bom)
	send("complete", map[string]interface{}{
		"count":  count,
		"result": string(out),
	})
	flush()
}

func (s *Server) handleCBOMImage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Image   string `json:"image"`
		Name    string `json:"name"`
		Plugins string `json:"plugins"`
		Ignore  string `json:"ignore"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, "invalid request: "+err.Error())
		return
	}
	if req.Image == "" {
		writeErr(w, "image is required")
		return
	}

	send, flush, ok := sseInit(w)
	if !ok {
		return
	}

	send("progress", progress(10, "Initialising image scanner…"))
	flush()

	opts := &cbom.Options{
		Image:   req.Image,
		Name:    req.Name,
		Plugins: req.Plugins,
		Ignore:  req.Ignore,
		Format:  "json",
	}

	send("progress", progress(30, "Pulling and scanning container image…"))
	flush()

	bom, err := cbom.GenerateFromImage(opts)
	if err != nil {
		send("error", errMsg(err))
		flush()
		return
	}

	send("progress", progress(80, "Building Cryptography BOM…"))
	flush()

	out, err := json.MarshalIndent(bom, "", "  ")
	if err != nil {
		send("error", errMsg(err))
		flush()
		return
	}

	count := cbom.ComponentCount(bom)
	send("complete", map[string]interface{}{
		"count":  count,
		"result": string(out),
	})
	flush()
}

func (s *Server) handleAIBOM(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ModelID      string `json:"modelId"`
		Token        string `json:"token"`
		Name         string `json:"name"`
		Version      string `json:"version"`
		Manufacturer string `json:"manufacturer"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, "invalid request: "+err.Error())
		return
	}
	if req.ModelID == "" {
		writeErr(w, "modelId is required")
		return
	}

	send, flush, ok := sseInit(w)
	if !ok {
		return
	}

	send("progress", progress(10, "Connecting to model registry…"))
	flush()

	opts := &aibom.Options{
		ModelID:      req.ModelID,
		Token:        req.Token,
		Name:         req.Name,
		Version:      req.Version,
		Manufacturer: req.Manufacturer,
		Format:       "json",
	}

	send("progress", progress(30, "Fetching model metadata…"))
	flush()

	bom, err := aibom.Generate(opts)
	if err != nil {
		send("error", errMsg(err))
		flush()
		return
	}

	send("progress", progress(80, "Building AI/ML BOM…"))
	flush()

	out, err := json.MarshalIndent(bom, "", "  ")
	if err != nil {
		send("error", errMsg(err))
		flush()
		return
	}

	count := aibom.ModelCount(bom)
	send("complete", map[string]interface{}{
		"count":  count,
		"result": string(out),
	})
	flush()
}

// handleRun executes an arbitrary knoxctl sub-command and streams its
// stdout/stderr line-by-line as SSE progress events.  Used for operations that
// are best delegated to the CLI (image-scan, probe, vm-onboard, etc.).
func (s *Server) handleRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Args []string `json:"args"` // knoxctl subcommand args, e.g. ["probe", "--full"]
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, "invalid request: "+err.Error())
		return
	}
	if len(req.Args) == 0 {
		writeErr(w, "args are required")
		return
	}

	send, flush, ok := sseInit(w)
	if !ok {
		return
	}

	self := resolveKnoxctl()

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, self, req.Args...) // #nosec G204
	cmd.Stdout = &lineWriter{send: send, flush: flush, event: "log"}
	cmd.Stderr = &lineWriter{send: send, flush: flush, event: "log"}

	send("progress", progress(10, "Running: knoxctl "+strings.Join(req.Args, " ")))
	flush()

	if err := cmd.Run(); err != nil {
		send("error", errMsg(err))
		flush()
		return
	}

	send("complete", map[string]interface{}{"message": "Command completed successfully."})
	flush()
}

// ──────────────────────────────────────────────────────────────────────────────
// SSE helpers
// ──────────────────────────────────────────────────────────────────────────────

type sendFn = func(event string, data interface{})

func sseInit(w http.ResponseWriter) (sendFn, func(), bool) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return nil, nil, false
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	send := func(event string, data interface{}) {
		b, _ := json.Marshal(data)
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, b)
	}
	flush := func() { flusher.Flush() }
	return send, flush, true
}

func progress(pct int, msg string) map[string]interface{} {
	return map[string]interface{}{"percent": pct, "message": msg}
}

func errMsg(err error) map[string]interface{} {
	return map[string]interface{}{"message": err.Error()}
}

// lineWriter streams each written chunk as an SSE event.
type lineWriter struct {
	send  sendFn
	flush func()
	event string
}

func (lw *lineWriter) Write(p []byte) (int, error) {
	lines := strings.Split(strings.TrimRight(string(p), "\n"), "\n")
	for _, line := range lines {
		if line != "" {
			lw.send(lw.event, map[string]string{"line": line})
			lw.flush()
		}
	}
	return len(p), nil
}

// ──────────────────────────────────────────────────────────────────────────────
// HTTP helpers
// ──────────────────────────────────────────────────────────────────────────────

func cors(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h(w, r)
	}
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// portFrom extracts the port number from "host:port".
func portFrom(addr string) string {
	parts := strings.SplitN(addr, ":", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	return addr
}

// resolveKnoxctl returns the path to the knoxctl binary.
// It checks the current working directory first, then falls back to PATH.
func resolveKnoxctl() string {
	binary := "knoxctl"
	if runtime.GOOS == "windows" {
		binary = "knoxctl.exe"
	}
	if cwd, err := os.Getwd(); err == nil {
		local := filepath.Join(cwd, binary)
		if info, err := os.Stat(local); err == nil && !info.IsDir() {
			return local
		}
	}
	if path, err := exec.LookPath(binary); err == nil {
		return path
	}
	return binary
}

// openBrowser opens url in the system default browser.
func openBrowser(url string) {
	var cmd string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		cmd, args = "open", []string{url}
	case "windows":
		cmd, args = "rundll32", []string{"url.dll,FileProtocolHandler", url}
	default:
		cmd, args = "xdg-open", []string{url}
	}
	_ = exec.Command(cmd, args...).Start() // #nosec G204
}

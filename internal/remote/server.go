package remote

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"netwatch/internal/aggregator"
)

//go:embed viewer.html
var viewerHTML []byte

// Server manages the read-only broadcast web viewer HTTP and SSE stream endpoint.
type Server struct {
	addr         string
	token        string
	statsManager *aggregator.StatsManager
	httpServer   *http.Server
}

// NewServer initializes a Server instance.
func NewServer(addr string, token string, sm *aggregator.StatsManager) *Server {
	return &Server{
		addr:         addr,
		token:        token,
		statsManager: sm,
	}
}

// Start launches the broadcast HTTP server.
func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()

	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/stream", s.handleStream)

	s.httpServer = &http.Server{
		Addr:    s.addr,
		Handler: mux,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = s.httpServer.Shutdown(shutdownCtx)
	}()

	fmt.Printf("🌐 Broadcast Remote Dashboard running at http://localhost%s (Token: '%s')\n", s.addr, s.token)
	err := s.httpServer.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

func (s *Server) authenticate(r *http.Request) bool {
	if s.token == "" {
		return true
	}
	queryToken := r.URL.Query().Get("token")
	return queryToken == s.token
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if !s.authenticate(r) {
		http.Error(w, "401 Unauthorized: Valid ?token= required", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(viewerHTML)
}

func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	if !s.authenticate(r) {
		http.Error(w, "401 Unauthorized: Valid ?token= required", http.StatusUnauthorized)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			snap := s.statsManager.GetSnapshot()
			data, err := json.Marshal(snap)
			if err != nil {
				continue
			}

			_, err = fmt.Fprintf(w, "data: %s\n\n", data)
			if err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

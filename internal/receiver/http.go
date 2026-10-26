package receiver

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"

	"github.com/kendallcoding202/kovyr-edr/internal/proof"
)

// Handler serves the v0 API (docs/api.md).
func (r *Receiver) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v0/challenge", r.handleChallenge)
	mux.HandleFunc("POST /v0/heartbeat", r.handleHeartbeat)
	mux.HandleFunc("GET /v0/status", r.handleStatus)
	mux.HandleFunc("POST /v0/enroll", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusNotImplemented, map[string]string{
			"error": "enrollment is a stub in v0: add the output of `kovyr-agent enroll --print-pubkey` to the devices file",
		})
	})
	return mux
}

func (r *Receiver) handleChallenge(w http.ResponseWriter, req *http.Request) {
	n, err := r.IssueNonce(req.URL.Query().Get("device"))
	switch {
	case errors.Is(err, ErrNotEnrolled):
		writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
		return
	case err != nil:
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
		return
	}
	// Exactly {"nonce":"<32 hex>"} in canonical JSON: the agent accepts
	// nothing else.
	b, _ := proof.EncodeCanonical(map[string]any{"nonce": hex.EncodeToString(n[:])})
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(append(b, '\n'))
}

func (r *Receiver) handleHeartbeat(w http.ResponseWriter, req *http.Request) {
	if mt, _, _ := mime.ParseMediaType(req.Header.Get("Content-Type")); mt != "application/json" {
		writeJSON(w, http.StatusUnsupportedMediaType, map[string]string{"error": "Content-Type must be application/json"})
		return
	}
	body, err := io.ReadAll(io.LimitReader(req.Body, proof.MaxEnvelopeBytes+1))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "read body"})
		return
	}
	if len(body) > proof.MaxEnvelopeBytes {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "envelope too large"})
		return
	}
	res := r.Receive(body)
	// The agent never reads this body; it is for people using curl.
	writeJSON(w, res.Status, map[string]any{"outcome": res.Outcome, "seq": res.Seq, "reason": res.Reason, "events": res.Events})
}

func (r *Receiver) handleStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, r.Status())
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

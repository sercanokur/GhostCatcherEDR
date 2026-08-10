package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

type termLine struct {
	Seq  int    `json:"seq"`
	Text string `json:"text"`
	Kind string `json:"kind,omitempty"` // cmd | out | meta | err
}

type termHub struct {
	mu      sync.Mutex
	seq     int
	lines   []termLine
	maxKeep int
	subs    map[chan termLine]struct{}
}

func newTermHub() *termHub {
	return &termHub{
		maxKeep: 4000,
		subs:    make(map[chan termLine]struct{}),
	}
}

func (h *termHub) Write(kind, text string) {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	parts := strings.Split(text, "\n")
	h.mu.Lock()
	defer h.mu.Unlock()
	for i, p := range parts {
		if p == "" && i == len(parts)-1 {
			continue
		}
		h.seq++
		line := termLine{Seq: h.seq, Text: p, Kind: kind}
		h.lines = append(h.lines, line)
		if len(h.lines) > h.maxKeep {
			h.lines = h.lines[len(h.lines)-h.maxKeep:]
		}
		h.broadcast(line)
	}
}

// broadcast must be called with h.mu held. Never drop: slow clients get a
// buffered drain; if still full, spill into a short-lived goroutine.
func (h *termHub) broadcast(line termLine) {
	for ch := range h.subs {
		select {
		case ch <- line:
		default:
			go func(c chan termLine, l termLine) {
				defer func() { _ = recover() }() // subscriber may have unsubscribed
				select {
				case c <- l:
				case <-time.After(2 * time.Second):
				}
			}(ch, line)
		}
	}
}

func (h *termHub) Printf(kind, format string, args ...any) {
	h.Write(kind, fmt.Sprintf(format, args...))
}

func (h *termHub) Snapshot() []termLine {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]termLine, len(h.lines))
	copy(out, h.lines)
	return out
}

func (h *termHub) Clear() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.lines = nil
	h.seq++
	line := termLine{Seq: h.seq, Text: "— terminal cleared —", Kind: "meta"}
	h.lines = append(h.lines, line)
	h.broadcast(line)
}

func (h *termHub) Subscribe() (chan termLine, func()) {
	ch := make(chan termLine, 512)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	unsub := func() {
		h.mu.Lock()
		delete(h.subs, ch)
		h.mu.Unlock()
		close(ch)
	}
	return ch, unsub
}

func (h *termHub) serveSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	// Subscribe before snapshot so lines produced during replay are not lost.
	ch, unsub := h.Subscribe()
	defer unsub()

	for _, line := range h.Snapshot() {
		writeSSE(w, line)
	}
	flusher.Flush()

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case line, ok := <-ch:
			if !ok {
				return
			}
			writeSSE(w, line)
			flusher.Flush()
		case <-ticker.C:
			_, _ = fmt.Fprintf(w, ": ping\n\n")
			flusher.Flush()
		}
	}
}

func writeSSE(w http.ResponseWriter, line termLine) {
	b, _ := json.Marshal(line)
	_, _ = fmt.Fprintf(w, "data: %s\n\n", b)
}

// termWriter streams SSH output into the hub as "out" lines.
type termWriter struct {
	hub  *termHub
	kind string
	buf  []byte
}

func (t *termWriter) Write(p []byte) (int, error) {
	t.buf = append(t.buf, p...)
	for {
		i := -1
		for j, c := range t.buf {
			if c == '\n' {
				i = j
				break
			}
		}
		if i < 0 {
			break
		}
		line := string(t.buf[:i])
		t.buf = t.buf[i+1:]
		line = strings.TrimRight(line, "\r")
		t.hub.Write(t.kind, line)
	}
	return len(p), nil
}

func (t *termWriter) Flush() {
	if len(t.buf) == 0 {
		return
	}
	t.hub.Write(t.kind, string(t.buf))
	t.buf = nil
}

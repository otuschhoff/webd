package server

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAccessLogMiddleware_LogsWebSocketStartAndCompletion(t *testing.T) {
	var out bytes.Buffer
	logger := log.New(&out, "", 0)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusSwitchingProtocols)
	})
	h := accessLogMiddleware(next, logger)

	req := httptest.NewRequest(http.MethodGet, "http://example.test/ws", nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("User-Agent", "test-agent")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 access log lines, got %d: %q", len(lines), out.String())
	}
	if !strings.Contains(lines[0], " s=ws_start ") {
		t.Fatalf("first log line missing websocket start marker: %q", lines[0])
	}
	if !strings.Contains(lines[1], " c=101 ") {
		t.Fatalf("second log line missing completion status: %q", lines[1])
	}
}

func TestAccessLogMiddleware_NonWebSocketLogsCompletionOnly(t *testing.T) {
	var out bytes.Buffer
	logger := log.New(&out, "", 0)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	h := accessLogMiddleware(next, logger)

	req := httptest.NewRequest(http.MethodGet, "http://example.test/health", nil)
	req.Header.Set("User-Agent", "test-agent")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected 1 access log line, got %d: %q", len(lines), out.String())
	}
	if strings.Contains(lines[0], " s=ws_start ") {
		t.Fatalf("non-websocket request should not include websocket start marker: %q", lines[0])
	}
	if !strings.Contains(lines[0], " c=204 ") {
		t.Fatalf("completion log line missing status: %q", lines[0])
	}
}

package server

import (
	"bufio"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// setupTestFileTree creates a temporary directory with the following layout:
//
//	base/
//	  file.txt           (regular file with content "hello")
//	  subdir/
//	    inner.txt        (regular file with content "inner")
//	  link_inside        (symlink → file.txt, within base)
//	  link_escape        (symlink → ../secret.txt, outside base)
//	  link_abs_escape    (symlink → absolute path outside base)
//	  broken_link        (symlink → nonexistent)
//
// It also creates secret.txt one level above base.
// Returns (baseDir, secretPath, cleanup).
func setupTestFileTree(t *testing.T) (baseDir, secretPath string) {
	t.Helper()
	root := t.TempDir()
	baseDir = filepath.Join(root, "base")

	if err := os.MkdirAll(filepath.Join(baseDir, "subdir"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(baseDir, "file.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(baseDir, "subdir", "inner.txt"), []byte("inner"), 0o644); err != nil {
		t.Fatal(err)
	}

	secretPath = filepath.Join(root, "secret.txt")
	if err := os.WriteFile(secretPath, []byte("secret-content"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Symlink that stays inside base.
	if err := os.Symlink("file.txt", filepath.Join(baseDir, "link_inside")); err != nil {
		t.Fatal(err)
	}
	// Symlink that escapes base via relative traversal.
	if err := os.Symlink("../secret.txt", filepath.Join(baseDir, "link_escape")); err != nil {
		t.Fatal(err)
	}
	// Symlink that escapes base via absolute path.
	if err := os.Symlink(secretPath, filepath.Join(baseDir, "link_abs_escape")); err != nil {
		t.Fatal(err)
	}
	// Broken symlink (target does not exist).
	if err := os.Symlink("nonexistent_file.txt", filepath.Join(baseDir, "broken_link")); err != nil {
		t.Fatal(err)
	}

	return baseDir, secretPath
}

// --- resolveTargetPath unit tests ---

func TestResolveTargetPath_RegularFile(t *testing.T) {
	baseDir, _ := setupTestFileTree(t)
	h := &localFileHandler{basePath: baseDir}

	got, err := h.resolveTargetPath("file.txt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasSuffix(got, "file.txt") {
		t.Errorf("got %q, want path ending in file.txt", got)
	}
}

func TestResolveTargetPath_SymlinkInsideBase(t *testing.T) {
	baseDir, _ := setupTestFileTree(t)
	h := &localFileHandler{basePath: baseDir}

	got, err := h.resolveTargetPath("link_inside")
	if err != nil {
		t.Fatalf("symlink inside base should be allowed, got error: %v", err)
	}
	// The returned path must be the resolved real path (file.txt), inside base.
	if !strings.Contains(got, baseDir) {
		t.Errorf("resolved path %q should be under baseDir %q", got, baseDir)
	}
}

// TestResolveTargetPath_SymlinkEscapeRelative is the regression test for the
// HIGH-severity symlink escape vulnerability fixed in commit 1e91259.
// A symlink inside the served directory that points outside via relative path
// (../secret.txt) must be blocked with a "path escapes base directory" error.
func TestResolveTargetPath_SymlinkEscapeRelative(t *testing.T) {
	baseDir, _ := setupTestFileTree(t)
	h := &localFileHandler{basePath: baseDir}

	_, err := h.resolveTargetPath("link_escape")
	if err == nil {
		t.Fatal("expected error for relative symlink escape, got nil")
	}
	if !strings.Contains(err.Error(), "path escapes base directory") {
		t.Errorf("expected 'path escapes base directory' error, got: %v", err)
	}
}

// TestResolveTargetPath_SymlinkEscapeAbsolute verifies that a symlink pointing
// to an absolute path outside the base directory is also blocked.
func TestResolveTargetPath_SymlinkEscapeAbsolute(t *testing.T) {
	baseDir, _ := setupTestFileTree(t)
	h := &localFileHandler{basePath: baseDir}

	_, err := h.resolveTargetPath("link_abs_escape")
	if err == nil {
		t.Fatal("expected error for absolute symlink escape, got nil")
	}
	if !strings.Contains(err.Error(), "path escapes base directory") {
		t.Errorf("expected 'path escapes base directory' error, got: %v", err)
	}
}

// TestResolveTargetPath_PathTraversal checks that lexical traversal via ../ in
// the URL path is also blocked (belt-and-suspenders with the symlink check).
func TestResolveTargetPath_PathTraversal(t *testing.T) {
	baseDir, _ := setupTestFileTree(t)
	h := &localFileHandler{basePath: baseDir}

	_, err := h.resolveTargetPath("../secret.txt")
	if err == nil {
		t.Fatal("expected error for ../ path traversal, got nil")
	}
}

// TestResolveTargetPath_BrokenSymlink verifies that a symlink whose target does
// not exist returns os.ErrNotExist (so the HTTP handler sends 404, not 403).
func TestResolveTargetPath_BrokenSymlink(t *testing.T) {
	baseDir, _ := setupTestFileTree(t)
	h := &localFileHandler{basePath: baseDir}

	_, err := h.resolveTargetPath("broken_link")
	if err == nil {
		t.Fatal("expected error for broken symlink, got nil")
	}
	// Must wrap os.ErrNotExist so ServeHTTP returns 404.
	if !isNotExist(err) {
		t.Errorf("expected error wrapping os.ErrNotExist, got: %v", err)
	}
}

// isNotExist mirrors os.IsNotExist but works with wrapped errors.
func isNotExist(err error) bool {
	return os.IsNotExist(err) || strings.Contains(err.Error(), "not found")
}

// --- ServeHTTP integration tests ---

func newTestHandler(t *testing.T, baseDir string) http.Handler {
	t.Helper()
	h, err := newLocalFileHandler("/", baseDir, false)
	if err != nil {
		t.Fatalf("newLocalFileHandler: %v", err)
	}
	return h
}

func TestServeHTTP_RegularFile(t *testing.T) {
	baseDir, _ := setupTestFileTree(t)
	h := newTestHandler(t, baseDir)

	req := httptest.NewRequest(http.MethodGet, "/file.txt", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("want 200, got %d", rec.Code)
	}
	if got := rec.Body.String(); got != "hello" {
		t.Errorf("want body %q, got %q", "hello", got)
	}
}

func TestServeHTTP_SymlinkInsideBase(t *testing.T) {
	baseDir, _ := setupTestFileTree(t)
	h := newTestHandler(t, baseDir)

	req := httptest.NewRequest(http.MethodGet, "/link_inside", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("symlink inside base: want 200, got %d", rec.Code)
	}
}

// TestServeHTTP_SymlinkEscapeRelativeBlocked is the HTTP-level regression test
// for the symlink escape vulnerability. Before the fix, GET /link_escape would
// return 200 and serve the content of ../secret.txt (outside the base dir).
// After the fix, it must return 403 Forbidden.
func TestServeHTTP_SymlinkEscapeRelativeBlocked(t *testing.T) {
	baseDir, _ := setupTestFileTree(t)
	h := newTestHandler(t, baseDir)

	req := httptest.NewRequest(http.MethodGet, "/link_escape", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("relative symlink escape: want 403, got %d (body: %s)", rec.Code, rec.Body.String())
	}
	// The response must not contain the secret file's content.
	if strings.Contains(rec.Body.String(), "secret-content") {
		t.Error("secret file content was leaked via relative symlink escape")
	}
}

// TestServeHTTP_SymlinkEscapeAbsoluteBlocked mirrors the above for absolute
// symlink targets.
func TestServeHTTP_SymlinkEscapeAbsoluteBlocked(t *testing.T) {
	baseDir, _ := setupTestFileTree(t)
	h := newTestHandler(t, baseDir)

	req := httptest.NewRequest(http.MethodGet, "/link_abs_escape", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("absolute symlink escape: want 403, got %d (body: %s)", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "secret-content") {
		t.Error("secret file content was leaked via absolute symlink escape")
	}
}

// TestServeHTTP_BrokenSymlinkReturns404 checks that a broken symlink inside the
// base directory produces 404, not 403, so callers can distinguish "does not
// exist" from "access denied".
func TestServeHTTP_BrokenSymlinkReturns404(t *testing.T) {
	baseDir, _ := setupTestFileTree(t)
	h := newTestHandler(t, baseDir)

	req := httptest.NewRequest(http.MethodGet, "/broken_link", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("broken symlink: want 404, got %d", rec.Code)
	}
}

func TestServeHTTP_PathTraversalBlocked(t *testing.T) {
	baseDir, _ := setupTestFileTree(t)
	h := newTestHandler(t, baseDir)

	// net/http normalises %2F, but double-dot traversal after URL decoding
	// should still be blocked.
	for _, path := range []string{"/../secret.txt", "/%2e%2e/secret.txt"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code == http.StatusOK {
			t.Errorf("path traversal %q: expected non-200 response, got 200 (body: %s)", path, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), "secret-content") {
			t.Errorf("path traversal %q: secret file content leaked", path)
		}
	}
}

// --- statusRecorder tests ---

// hijackableRecorder wraps httptest.ResponseRecorder and implements
// http.Hijacker so we can verify that statusRecorder.Hijack delegates correctly.
type hijackableRecorder struct {
	*httptest.ResponseRecorder
	hijackCalled bool
}

func (h *hijackableRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h.hijackCalled = true
	return nil, nil, nil
}

// TestStatusRecorder_HijackDelegates is the regression test for WebSocket
// proxy failures caused by statusRecorder not implementing http.Hijacker.
// Before the fix, the WebSocket proxy would error with
// "can't switch protocols using non-Hijacker ResponseWriter type *server.statusRecorder".
func TestStatusRecorder_HijackDelegates(t *testing.T) {
	inner := &hijackableRecorder{ResponseRecorder: httptest.NewRecorder()}
	var rw http.ResponseWriter = &statusRecorder{ResponseWriter: inner}

	hijacker, ok := rw.(http.Hijacker)
	if !ok {
		t.Fatal("statusRecorder does not implement http.Hijacker")
	}
	hijacker.Hijack()
	if !inner.hijackCalled {
		t.Error("Hijack() was not delegated to the underlying ResponseWriter")
	}
}

// TestStatusRecorder_HijackErrorsWhenNotSupported verifies that Hijack returns
// an error (rather than panicking) when the underlying ResponseWriter does not
// implement http.Hijacker.
func TestStatusRecorder_HijackErrorsWhenNotSupported(t *testing.T) {
	var rw http.ResponseWriter = &statusRecorder{ResponseWriter: httptest.NewRecorder()}

	hijacker, ok := rw.(http.Hijacker)
	if !ok {
		t.Fatal("statusRecorder does not implement http.Hijacker")
	}
	_, _, err := hijacker.Hijack()
	if err == nil {
		t.Error("expected error when underlying ResponseWriter is not a Hijacker, got nil")
	}
}

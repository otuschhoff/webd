package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- ensureSymlink tests ---

// TestEnsureSymlink_Create verifies that ensureSymlink creates a new symlink
// when none exists at the destination path.
func TestEnsureSymlink_Create(t *testing.T) {
	dir := t.TempDir()
	target := "real.txt"
	linkPath := filepath.Join(dir, "link")

	// Create the real file so EvalSymlinks works if needed elsewhere, but
	// ensureSymlink itself does not require the target to exist.
	if err := os.WriteFile(filepath.Join(dir, target), []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := ensureSymlink(linkPath, target); err != nil {
		t.Fatalf("ensureSymlink create: %v", err)
	}

	got, err := os.Readlink(linkPath)
	if err != nil {
		t.Fatalf("Readlink: %v", err)
	}
	if got != target {
		t.Errorf("symlink target: want %q, got %q", target, got)
	}
}

// TestEnsureSymlink_Idempotent verifies that calling ensureSymlink a second
// time with the same target is a no-op and returns nil.
func TestEnsureSymlink_Idempotent(t *testing.T) {
	dir := t.TempDir()
	target := "real.txt"
	linkPath := filepath.Join(dir, "link")

	if err := os.WriteFile(filepath.Join(dir, target), []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ensureSymlink(linkPath, target); err != nil {
		t.Fatalf("first call: %v", err)
	}
	if err := ensureSymlink(linkPath, target); err != nil {
		t.Fatalf("second (idempotent) call: %v", err)
	}

	got, err := os.Readlink(linkPath)
	if err != nil {
		t.Fatal(err)
	}
	if got != target {
		t.Errorf("want %q, got %q", target, got)
	}
}

// TestEnsureSymlink_UpdateExisting_IsAtomic is the regression test for the
// TOCTOU vulnerability fixed in commit 8361183. The old code did
// os.Remove(path) followed by os.Symlink(target, path), leaving a window where
// the path did not exist. The new code creates a temp symlink then calls
// os.Rename (which is atomic on Linux/macOS) to swap it into place.
//
// This test verifies the externally observable result of the fix: an existing
// symlink with a different target is correctly replaced without error.
func TestEnsureSymlink_UpdateExisting_IsAtomic(t *testing.T) {
	dir := t.TempDir()
	oldTarget := "old.txt"
	newTarget := "new.txt"
	linkPath := filepath.Join(dir, "link")

	for _, name := range []string{oldTarget, newTarget} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(name), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// Create with old target first.
	if err := ensureSymlink(linkPath, oldTarget); err != nil {
		t.Fatalf("initial create: %v", err)
	}

	// Now update to new target.
	if err := ensureSymlink(linkPath, newTarget); err != nil {
		t.Fatalf("update: %v", err)
	}

	got, err := os.Readlink(linkPath)
	if err != nil {
		t.Fatal(err)
	}
	if got != newTarget {
		t.Errorf("after update want %q, got %q", newTarget, got)
	}
}

// TestEnsureSymlink_NoTempFileLeftOnSuccess verifies that no temporary
// ".symtmpNNN" artefact is left in the directory after a successful call.
func TestEnsureSymlink_NoTempFileLeftOnSuccess(t *testing.T) {
	dir := t.TempDir()
	target := "real.txt"
	linkPath := filepath.Join(dir, "link")

	if err := os.WriteFile(filepath.Join(dir, target), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ensureSymlink(linkPath, target); err != nil {
		t.Fatalf("ensureSymlink: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".symtmp") {
			t.Errorf("unexpected temp artefact left behind: %s", e.Name())
		}
	}
}

// TestEnsureSymlink_BlocksNonSymlinkReplacement checks that ensureSymlink
// refuses to replace a regular file (or directory) at the destination path.
func TestEnsureSymlink_BlocksNonSymlinkReplacement(t *testing.T) {
	dir := t.TempDir()
	linkPath := filepath.Join(dir, "notasymlink")

	// Create a regular file at the link path.
	if err := os.WriteFile(linkPath, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}

	err := ensureSymlink(linkPath, "other.txt")
	if err == nil {
		t.Fatal("expected error when destination is a regular file, got nil")
	}
	if !strings.Contains(err.Error(), "cannot replace non-symlink") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// TestEnsureSymlink_CreatesParentDirs verifies that missing parent directories
// are created automatically.
func TestEnsureSymlink_CreatesParentDirs(t *testing.T) {
	dir := t.TempDir()
	linkPath := filepath.Join(dir, "a", "b", "c", "link")

	if err := ensureSymlink(linkPath, "target.txt"); err != nil {
		t.Fatalf("ensureSymlink with missing parents: %v", err)
	}

	if _, err := os.Lstat(linkPath); errors.Is(err, os.ErrNotExist) {
		t.Error("symlink was not created")
	}
}

package recovery

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestDigestFileRejectsSymlinkedParentDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on Windows runners")
	}
	root := t.TempDir()
	outside := t.TempDir()
	outsideSHA := filepath.Join(outside, "sha256")
	if err := os.MkdirAll(outsideSHA, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outsideSHA, "model.npy"), []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "artifacts")); err != nil {
		t.Fatal(err)
	}
	if _, err := DigestFile(root, "artifacts/sha256/model.npy"); err == nil {
		t.Fatal("recovery bundle file beneath a symlinked parent directory was accepted")
	}
}

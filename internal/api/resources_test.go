package api

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDirectorySizeCountsRegularFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "archive"), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "current.log"), []byte("12345"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "archive", "old.log"), []byte("123"), 0600); err != nil {
		t.Fatal(err)
	}
	size, err := directorySize(dir)
	if err != nil {
		t.Fatal(err)
	}
	if size != 8 {
		t.Fatalf("directory size = %d, want 8", size)
	}
}

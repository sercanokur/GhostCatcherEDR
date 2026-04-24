package web

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"

	"ghostcatcher/internal/baseline"
	"ghostcatcher/internal/config"
)

// BuildBaselineWebFiles records hashes and mtimes for scanned web roots.
func BuildBaselineWebFiles(cfg *config.Config, snap *baseline.Snapshot) error {
	if snap.WebFiles == nil {
		snap.WebFiles = make(map[string]baseline.WebFileRecord)
	}
	for _, root := range cfg.DocumentRoots {
		root = filepath.Clean(root)
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			if !stringsHasSuffixFold(path, ".php") && !stringsHasSuffixFold(path, ".phtml") && !stringsHasSuffixFold(path, ".jsp") {
				return nil
			}
			if pathAllowlisted(path, cfg.PathAllowlist) {
				return nil
			}
			st, err := d.Info()
			if err != nil {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			sum := sha256.Sum256(data)
			snap.WebFiles[path] = baseline.WebFileRecord{
				SHA256: hex.EncodeToString(sum[:]),
				Mtime:  st.ModTime().UTC(),
			}
			return nil
		})
	}
	return nil
}

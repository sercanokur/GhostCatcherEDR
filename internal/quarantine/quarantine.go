// Package quarantine copies high-confidence web shell / memfd-created
// files into a tamper-resistant evidence vault. Files are stored under
// <vault>/<YYYYMMDD>/<sha256>.bin along with a sidecar .json capturing
// the original path, UID/GID/mode, mtime, and triggering rule. The
// vault directory is created with 0700 and all files with 0400 so the
// running agent user can write but no one else can modify.
package quarantine

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"ghostcatcher/internal/event"
)

type Vault struct {
	dir string
}

func New(dir string) (*Vault, error) {
	if dir == "" {
		return nil, errors.New("quarantine: dir required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &Vault{dir: dir}, nil
}

// Store copies the bytes of path into the vault and writes a sidecar.
// The original file is NOT deleted (we leave eradication to the IR
// team); this keeps the agent from becoming a liability on a legitimate
// file.
func (v *Vault) Store(path string, e *event.Event) (string, error) {
	src, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer src.Close()
	fi, err := src.Stat()
	if err != nil {
		return "", err
	}
	h := sha256.New()
	day := time.Now().UTC().Format("20060102")
	if err := os.MkdirAll(filepath.Join(v.dir, day), 0o700); err != nil {
		return "", err
	}
	tmp := filepath.Join(v.dir, day, "partial.tmp")
	dst, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o400)
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(io.MultiWriter(dst, h), src); err != nil {
		dst.Close()
		_ = os.Remove(tmp)
		return "", err
	}
	dst.Close()
	sum := hex.EncodeToString(h.Sum(nil))
	final := filepath.Join(v.dir, day, sum+".bin")
	if err := os.Rename(tmp, final); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	side := map[string]interface{}{
		"path":        path,
		"sha256":      sum,
		"size":        fi.Size(),
		"mtime":       fi.ModTime().UTC().Format(time.RFC3339Nano),
		"mode":        fi.Mode().String(),
		"stored_at":   time.Now().UTC().Format(time.RFC3339Nano),
		"rule_id":     e.RuleID,
		"confidence":  e.Confidence,
		"signals":     e.Signals,
	}
	jb, _ := json.MarshalIndent(side, "", "  ")
	_ = os.WriteFile(filepath.Join(v.dir, day, sum+".json"), jb, 0o400)
	return final, nil
}

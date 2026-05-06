// Package selfguard hardens the agent against in-place tampering.
// Two checks run on every scan interval:
//
//   1. BinaryHash: sha256 of the configured binary matches the value
//      captured at install time. Mismatch emits a critical event.
//   2. SystemdWatchdog: if the agent was launched under systemd with
//      WatchdogSec set, we notify "WATCHDOG=1" so systemd restarts us
//      on hang.
package selfguard

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// BinaryMatches hashes the binary at path and returns nil if it equals
// expected (hex sha256). Non-matching returns a descriptive error for
// the caller to include in an event.
func BinaryMatches(path, expected string) error {
	if path == "" || expected == "" {
		return errors.New("selfguard: path/expected required")
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	got := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(got, expected) {
		return &MismatchError{Path: path, Got: got, Want: expected}
	}
	return nil
}

type MismatchError struct {
	Path     string
	Got      string
	Want     string
}

func (e *MismatchError) Error() string {
	return "selfguard: binary hash mismatch for " + e.Path + " got=" + e.Got + " want=" + e.Want
}

// NotifyWatchdog sends "WATCHDOG=1" to $NOTIFY_SOCKET if the socket is
// configured by systemd. No error on missing env because callers invoke
// this on a cadence — a silent no-op is desirable when running outside
// systemd.
func NotifyWatchdog() error {
	addr := os.Getenv("NOTIFY_SOCKET")
	if addr == "" {
		return nil
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: addr, Net: "unixgram"})
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write([]byte("WATCHDOG=1"))
	return err
}

// WatchdogInterval returns WatchdogSec / 2 as a time.Duration, respecting
// the systemd convention. Returns 0 if WATCHDOG_USEC is not set.
func WatchdogInterval() time.Duration {
	u := os.Getenv("WATCHDOG_USEC")
	if u == "" {
		return 0
	}
	us, err := strconv.ParseInt(u, 10, 64)
	if err != nil || us <= 0 {
		return 0
	}
	return time.Duration(us/2) * time.Microsecond
}

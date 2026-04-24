package baseline

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSnapshotRoundTrip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "b.json")
	s := EmptySnapshot()
	s.AuthKeys["/root/.ssh/authorized_keys"] = []string{"SHA256:abc"}
	s.CronLines["/etc/crontab"] = []string{"deadbeef"}
	s.WebFiles["/var/www/a.php"] = WebFileRecord{SHA256: "x", Mtime: time.Unix(1, 0).UTC()}
	s.LDPreload = []string{"/lib/x.so"}
	s.CommittedAt = time.Now().UTC()
	if err := s.Save(p); err != nil {
		t.Fatal(err)
	}
	l, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(l.AuthKeys["/root/.ssh/authorized_keys"]) != 1 {
		t.Fatal()
	}
	if !l.IsCommitted() {
		t.Fatal()
	}
	_ = os.Remove(p)
}

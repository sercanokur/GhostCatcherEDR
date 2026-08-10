package watch

import (
	"path/filepath"
	"testing"
)

func TestDefaultSensitivePaths_OmitsLiveLogs(t *testing.T) {
	specs := DefaultSensitivePaths(nil)
	for _, s := range specs {
		switch s.Path {
		case "/var/log/auth.log", "/var/log/syslog":
			t.Fatalf("live log path should not be watched: %s", s.Path)
		}
	}
	var sawRsyslog bool
	for _, s := range specs {
		if s.Path == "/etc/rsyslog.conf" || s.Path == "/etc/rsyslog.d" {
			sawRsyslog = true
		}
	}
	if !sawRsyslog {
		t.Fatal("expected rsyslog config watches for M4.2")
	}
}

func TestDefaultSensitivePaths_DocrootFilterNested(t *testing.T) {
	root := "/var/www/html"
	specs := DefaultSensitivePaths([]string{root})
	var filter func(string) bool
	for _, s := range specs {
		if s.Path == root {
			filter = s.FilenameFilter
			break
		}
	}
	if filter == nil {
		t.Fatal("missing docroot FilenameFilter")
	}
	if !filter("shell.php") {
		t.Fatal("expected .php to pass filter")
	}
	if filter("readme.txt") {
		t.Fatal("expected .txt to fail filter")
	}
	nested := filepath.Join(root, "uploads", "x.php")
	if !pathUnder(root, nested) {
		t.Fatalf("pathUnder(%q, %q) = false", root, nested)
	}
}

func TestPathUnder(t *testing.T) {
	cases := []struct {
		root, path string
		want       bool
	}{
		{"/var/www", "/var/www", true},
		{"/var/www", "/var/www/html/a.php", true},
		{"/var/www", "/var/www2/html", false},
		{"/var/www", "/tmp/x", false},
		{"", "/var/www", false},
	}
	for _, tc := range cases {
		if got := pathUnder(tc.root, tc.path); got != tc.want {
			t.Fatalf("pathUnder(%q, %q)=%v want %v", tc.root, tc.path, got, tc.want)
		}
	}
}

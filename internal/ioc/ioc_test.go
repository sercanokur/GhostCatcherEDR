package ioc

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestFeed_HashIPDomain(t *testing.T) {
	dir := t.TempDir()
	hp := filepath.Join(dir, "hashes.txt")
	ip := filepath.Join(dir, "ips.txt")
	dp := filepath.Join(dir, "doms.txt")
	_ = os.WriteFile(hp, []byte("deadbeef\n# comment\n"), 0o644)
	_ = os.WriteFile(ip, []byte("10.0.0.1\n192.168.2.0/24\n"), 0o644)
	_ = os.WriteFile(dp, []byte("evil.example\n"), 0o644)
	f := NewFeed()
	if err := f.Load([]string{hp}, []string{ip}, []string{dp}); err != nil {
		t.Fatal(err)
	}
	if !f.MatchHash("DEADBEEF") {
		t.Fatal("hash case-insensitive")
	}
	if !f.MatchIP(net.ParseIP("10.0.0.1")) {
		t.Fatal("ip exact")
	}
	if !f.MatchIP(net.ParseIP("192.168.2.5")) {
		t.Fatal("cidr range")
	}
	if !f.MatchDomain("sub.evil.example") {
		t.Fatal("domain suffix match")
	}
}

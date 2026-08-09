package anchor

import "testing"

func TestFromCgroupSystemSlice(t *testing.T) {
	info := FromCgroup("0::/system.slice/nginx.service")
	if info.SystemdUnit != "nginx.service" {
		t.Fatalf("unit=%q", info.SystemdUnit)
	}
	if info.Anchor != "nginx.service" {
		t.Fatalf("anchor=%q", info.Anchor)
	}
}

func TestFromCgroupV1(t *testing.T) {
	info := FromCgroup("12:name=systemd:/system.slice/php8.1-fpm.service")
	if info.SystemdUnit != "php8.1-fpm.service" {
		t.Fatalf("unit=%q", info.SystemdUnit)
	}
}

func TestIsWatchedUnit(t *testing.T) {
	watched := []string{"nginx.service", "php-fpm", "apache2"}
	if !IsWatchedUnit("nginx.service", watched) {
		t.Fatal("nginx should match")
	}
	if !IsWatchedUnit("php8.3-fpm.service", watched) {
		t.Fatal("php-fpm prefix should match")
	}
	if IsWatchedUnit("cron.service", watched) {
		t.Fatal("cron should not match")
	}
}

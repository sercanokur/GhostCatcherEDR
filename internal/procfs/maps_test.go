package procfs

import "testing"

func TestHasRWXSegment(t *testing.T) {
	entries := []MapEntry{{Perms: "r-xp", Pathname: "/bin/ls"}}
	if ok, _ := HasRWXSegment(entries); ok {
		t.Fatal("r-xp should not match")
	}
	entries = append(entries, MapEntry{Perms: "rwxp", Pathname: ""})
	if ok, _ := HasRWXSegment(entries); !ok {
		t.Fatal("expected rwxp anonymous")
	}
	entries = []MapEntry{{Perms: "rwxp", Pathname: "[vdso]"}}
	if ok, _ := HasRWXSegment(entries); ok {
		t.Fatal("vdso skipped")
	}
}

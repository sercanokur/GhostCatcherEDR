package container

import "testing"

func TestClassify_Docker(t *testing.T) {
	// 64 hex chars
	id := "5f2cd1b0deadbeef1234567890abcdef1234567890abcdef1234567890abcdef"
	in := "12:cpuset:/docker/" + id + "\n"
	got := Classify(in)
	if got.Runtime != "docker" {
		t.Fatalf("runtime: %s", got.Runtime)
	}
	if got.ID != "5f2cd1b0dead" {
		t.Fatalf("id: %s", got.ID)
	}
}

func TestClassify_K8s(t *testing.T) {
	in := "0::/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod1234abcd_5678_90ab_cdef_0123456789ab.slice/cri-containerd-0123abcd.scope"
	got := Classify(in)
	if got.PodUID == "" {
		t.Fatalf("podUID missing: %+v", got)
	}
	if got.Runtime == "" {
		t.Fatal("runtime missing")
	}
}

func TestClassify_Host(t *testing.T) {
	if !Classify("0::/\n").IsZero() {
		t.Fatal("root cgroup should classify as host")
	}
}

package web

import "testing"

func TestTaintFlow_DirectSink(t *testing.T) {
	src := `<?php eval($_POST['cmd']); ?>`
	hit, sink := scanPHPTaintFlow(src)
	if !hit || sink != "eval" {
		t.Fatalf("expected eval sink hit, got %v %q", hit, sink)
	}
}

func TestTaintFlow_ThroughVar(t *testing.T) {
	src := `<?php $x = $_GET['p']; system($x); ?>`
	hit, sink := scanPHPTaintFlow(src)
	if !hit || sink != "system" {
		t.Fatalf("expected system hit via $x, got %v %q", hit, sink)
	}
}

func TestTaintFlow_Sanitized(t *testing.T) {
	src := `<?php $x = "static"; system($x); ?>`
	hit, _ := scanPHPTaintFlow(src)
	if hit {
		t.Fatal("literal assignment should clear taint")
	}
}

func TestTaintFlow_NoPHP(t *testing.T) {
	src := `<html>hello</html>`
	if hit, _ := scanPHPTaintFlow(src); hit {
		t.Fatal("non-php must not match")
	}
}

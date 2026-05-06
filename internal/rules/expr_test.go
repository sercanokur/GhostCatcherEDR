package rules

import "testing"

func eval(t *testing.T, src string, f EventFacts) bool {
	t.Helper()
	e, err := CompileExpr(src)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	b, err := e.Eval(f)
	if err != nil {
		t.Fatalf("eval: %v (src=%s)", err, src)
	}
	return b
}

func TestExpr_SignalAndBool(t *testing.T) {
	f := EventFacts{Signals: []string{"rwx_memory_mapping"}, Confidence: 80}
	if !eval(t, `signal("rwx_memory_mapping") and confidence >= 70`, f) {
		t.Fatal("expected true")
	}
}

func TestExpr_NotOr(t *testing.T) {
	f := EventFacts{Signals: []string{"a"}, Tactic: "persistence"}
	if !eval(t, `not signal("x") or tactic == "persistence"`, f) {
		t.Fatal("expected true")
	}
}

func TestExpr_InList(t *testing.T) {
	f := EventFacts{Comm: "bash"}
	if !eval(t, `comm in ["sh","bash","zsh"]`, f) {
		t.Fatal("expected true")
	}
}

func TestExpr_ContainsMatches(t *testing.T) {
	f := EventFacts{EntityPath: "/tmp/evil.so"}
	if !eval(t, `entity_path contains "/tmp/"`, f) {
		t.Fatal()
	}
	if !eval(t, `matches(entity_path, "^/tmp/.*\\.so$")`, f) {
		t.Fatal()
	}
}

func TestExpr_EmptyTrue(t *testing.T) {
	e, err := CompileExpr("")
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := e.Eval(EventFacts{}); !b {
		t.Fatal("empty must be true")
	}
}

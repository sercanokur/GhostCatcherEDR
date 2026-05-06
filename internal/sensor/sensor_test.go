package sensor

import "testing"

func TestParseAuditLine_Exec(t *testing.T) {
	line := `type=SYSCALL msg=audit(1700000000.000:1): syscall=59 success=yes pid=1234 ppid=1 uid=0 comm="bash"`
	ev, ok := parseAuditLine(line)
	if !ok || ev.Kind != KindExec || ev.PID != 1234 || ev.Comm != "bash" {
		t.Fatalf("unexpected parse: %+v ok=%v", ev, ok)
	}
}

func TestParseAuditLine_Ignores(t *testing.T) {
	line := `type=USER_ACCT msg=...`
	if _, ok := parseAuditLine(line); ok {
		t.Fatal("should have been ignored")
	}
}

func TestParseAuditLine_Unknown(t *testing.T) {
	line := `type=SYSCALL syscall=99999`
	if _, ok := parseAuditLine(line); ok {
		t.Fatal("unknown syscall should be dropped")
	}
}

// TestParseAuditLine_SocketCapturesArgs ensures that for the socket()
// syscall (x86_64 nr=41) we propagate the hex-encoded a0/a1/a2 args
// through Extra, since the CVE-2026-31431 detector keys off them.
func TestParseAuditLine_SocketCapturesArgs(t *testing.T) {
	line := `type=SYSCALL msg=audit(1700000000.000:42): syscall=41 success=yes exit=3 a0=26 a1=5 a2=0 pid=4242 ppid=4000 uid=1000 comm="exploit"`
	ev, ok := parseAuditLine(line)
	if !ok || ev.Kind != KindSocket {
		t.Fatalf("expected socket kind, got %+v ok=%v", ev, ok)
	}
	if ev.Extra == nil {
		t.Fatal("Extra not populated for socket()")
	}
	if ev.Extra["a0"] != "26" || ev.Extra["a1"] != "5" {
		t.Fatalf("Extra missing AF_ALG/SEQPACKET args: %+v", ev.Extra)
	}
	if ev.Extra["success"] != "yes" {
		t.Fatalf("Extra missing success flag: %+v", ev.Extra)
	}
}

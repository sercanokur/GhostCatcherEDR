package copyfail

import (
	"testing"

	"ghostcatcher/internal/config"
	"ghostcatcher/internal/rules"
	"ghostcatcher/internal/sensor"
)

// testPack returns a minimal in-memory pack carrying both copyfail
// rules so RouteSensorEvent / Scan can compute confidence without
// loading YAML from disk.
func testPack() *rules.Pack {
	return &rules.Pack{
		Version: "test",
		Rules: []rules.Rule{
			{ID: RuleAFAlgAEAD, Techniques: []string{"T1068"}, Tactic: "privilege-escalation", MinSignals: 1, BaseScore: 90, PerSignal: 5, CapScore: 100},
			{ID: RulePageCachePois, Techniques: []string{"T1068", "T1014"}, Tactic: "privilege-escalation", MinSignals: 1, BaseScore: 95, PerSignal: 5, CapScore: 100},
		},
	}
}

// TestRouteSensorEvent_FlagsAFAlgFromUntrustedComm ensures the
// canonical CVE-2026-31431 socket() shape (domain=AF_ALG=38, type=
// SOCK_SEQPACKET=5) coming from a non-allowlisted process raises the
// AF_ALG AEAD rule.
func TestRouteSensorEvent_FlagsAFAlgFromUntrustedComm(t *testing.T) {
	cfg := config.Default()
	pack := testPack()
	ev := sensor.Event{
		Kind: sensor.KindSocket,
		PID:  4242,
		Comm: "evil",
		Extra: map[string]string{
			"a0":      "26", // AF_ALG
			"a1":      "5",  // SOCK_SEQPACKET
			"success": "yes",
		},
	}
	out, hit := RouteSensorEvent(cfg, pack, "test", ev)
	if !hit {
		t.Fatal("expected detection on AF_ALG SEQPACKET from untrusted comm")
	}
	if out.RuleID != RuleAFAlgAEAD {
		t.Fatalf("rule_id=%q want %q", out.RuleID, RuleAFAlgAEAD)
	}
	if out.Confidence < 90 {
		t.Fatalf("confidence=%d want >=90", out.Confidence)
	}
}

// TestRouteSensorEvent_AllowsCryptsetup makes sure the agent does NOT
// alert on the disk-encryption tooling that legitimately opens AF_ALG
// sockets — otherwise every reboot of an encrypted-root host would
// fire CRITICAL noise.
func TestRouteSensorEvent_AllowsCryptsetup(t *testing.T) {
	cfg := config.Default()
	pack := testPack()
	for _, comm := range []string{"cryptsetup", "systemd-cryptse", "veritysetup"} {
		ev := sensor.Event{
			Kind: sensor.KindSocket,
			PID:  1,
			Comm: comm,
			Extra: map[string]string{
				"a0":      "26",
				"a1":      "80005", // SOCK_SEQPACKET | SOCK_CLOEXEC
				"success": "yes",
			},
		}
		if _, hit := RouteSensorEvent(cfg, pack, "test", ev); hit {
			t.Fatalf("comm=%q should be allowlisted", comm)
		}
	}
}

// TestRouteSensorEvent_IgnoresHashOnlyAFAlgUsers covers the false-
// positive surface flagged by the Sysdig writeup: AF_ALG hashing /
// symmetric crypto callers use SOCK_DGRAM (type=2) and would create
// a torrent of alerts if matched. We must skip them.
func TestRouteSensorEvent_IgnoresHashOnlyAFAlgUsers(t *testing.T) {
	cfg := config.Default()
	pack := testPack()
	ev := sensor.Event{
		Kind: sensor.KindSocket,
		PID:  100,
		Comm: "anything",
		Extra: map[string]string{
			"a0":      "26",
			"a1":      "2", // SOCK_DGRAM — hashing/symmetric, not AEAD
			"success": "yes",
		},
	}
	if _, hit := RouteSensorEvent(cfg, pack, "test", ev); hit {
		t.Fatal("DGRAM AF_ALG should be ignored to avoid hashing-call false positives")
	}
}

// TestRouteSensorEvent_IgnoresOtherDomains guards against accidentally
// matching AF_INET/AF_UNIX SEQPACKET sockets (rare, but they exist).
func TestRouteSensorEvent_IgnoresOtherDomains(t *testing.T) {
	cfg := config.Default()
	pack := testPack()
	ev := sensor.Event{
		Kind: sensor.KindSocket,
		PID:  100,
		Comm: "anything",
		Extra: map[string]string{
			"a0":      "1", // AF_UNIX
			"a1":      "5",
			"success": "yes",
		},
	}
	if _, hit := RouteSensorEvent(cfg, pack, "test", ev); hit {
		t.Fatal("non-AF_ALG sockets must not match")
	}
}

// TestRouteSensorEvent_IgnoresFailedSyscall avoids alerting on EACCES
// failures from sandboxed callers that try and fail to open AF_ALG.
func TestRouteSensorEvent_IgnoresFailedSyscall(t *testing.T) {
	cfg := config.Default()
	pack := testPack()
	ev := sensor.Event{
		Kind: sensor.KindSocket,
		PID:  100,
		Comm: "evil",
		Extra: map[string]string{
			"a0":      "26",
			"a1":      "5",
			"success": "no",
			"exit":    "-13", // EACCES
		},
	}
	if _, hit := RouteSensorEvent(cfg, pack, "test", ev); hit {
		t.Fatal("failed socket() must not alert")
	}
}

// TestRouteSensorEvent_AcceptsTypeWithCloexecFlags exercises the flag
// masking — real AF_ALG callers in the public PoCs OR in SOCK_CLOEXEC
// (0x80000) and/or SOCK_NONBLOCK (0x800), so 0x80005 / 0x80805 must
// still match.
func TestRouteSensorEvent_AcceptsTypeWithCloexecFlags(t *testing.T) {
	cfg := config.Default()
	pack := testPack()
	for _, t1 := range []string{"80005", "80805", "805"} {
		ev := sensor.Event{
			Kind: sensor.KindSocket,
			PID:  9,
			Comm: "exploit",
			Extra: map[string]string{
				"a0":      "26",
				"a1":      t1,
				"success": "yes",
			},
		}
		if _, hit := RouteSensorEvent(cfg, pack, "test", ev); !hit {
			t.Fatalf("type=0x%s should still match SOCK_SEQPACKET after flag masking", t1)
		}
	}
}

// TestParseHexInt covers the parser used to decode audit's hex args.
func TestParseHexInt(t *testing.T) {
	cases := map[string]int{
		"26":    0x26,
		"0x26":  0x26,
		"5":     5,
		"80005": 0x80005,
		"0x805": 0x805,
	}
	for in, want := range cases {
		got, ok := parseHexInt(in)
		if !ok || got != want {
			t.Fatalf("parseHexInt(%q)=%d ok=%v want %d", in, got, ok, want)
		}
	}
	if _, ok := parseHexInt(""); ok {
		t.Fatal("empty string should fail")
	}
	if _, ok := parseHexInt("zz"); ok {
		t.Fatal("non-hex should fail")
	}
}

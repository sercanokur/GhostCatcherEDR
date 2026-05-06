package syslog

import (
	"strings"
	"testing"
	"time"
)

func TestFormatRFC5424(t *testing.T) {
	s := formatRFC5424(165, time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC),
		"web01", "ghostcatcher", "1234", "RULE", `{"a":1}`)
	if !strings.HasPrefix(s, "<165>1 ") {
		t.Fatal(s)
	}
	if !strings.HasSuffix(s, ` {"a":1}`) {
		t.Fatal(s)
	}
}

func TestTrimToMax(t *testing.T) {
	long := make([]byte, 1000)
	b := trimToMax(long, 20)
	if len(b) != 20 {
		t.Fatal(len(b))
	}
}

func TestNewUDP_disabled(t *testing.T) {
	c, err := NewUDP(Config{Enabled: false})
	if err != nil || c != nil {
		t.Fatalf("got c=%v err=%v", c, err)
	}
}

func TestParseFacility(t *testing.T) {
	f, err := parseFacility("local1")
	if err != nil || f != 17 {
		t.Fatal(f, err)
	}
}

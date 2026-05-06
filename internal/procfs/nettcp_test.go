package procfs

import "testing"

func TestParseHexAddr_IPv4(t *testing.T) {
	ip, p, err := parseHexAddr("0100007F:1F90")
	if err != nil {
		t.Fatal(err)
	}
	if ip.String() != "127.0.0.1" {
		t.Fatalf("got %s", ip)
	}
	if p != 0x1F90 {
		t.Fatalf("got port %d", p)
	}
}

func TestParseHexAddr_IPv6(t *testing.T) {
	// ::1 is 0000:0000:0000:0000:0000:0000:0000:0001 -> hex (little-endian per u32) is 00000000 00000000 00000000 01000000
	_, _, err := parseHexAddr("00000000000000000000000001000000:0050")
	if err != nil {
		t.Fatal(err)
	}
}

package procfs

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

// TCPState is the TCP_STATE enum used by /proc/net/tcp[6].
type TCPState uint8

const (
	TCPEstablished TCPState = 0x01
	TCPSynSent     TCPState = 0x02
	TCPListen      TCPState = 0x0a
)

// SocketRow is one decoded entry from /proc/net/tcp[6] or /proc/net/udp[6].
type SocketRow struct {
	Proto   string // "tcp" | "tcp6" | "udp" | "udp6"
	Local   net.IP
	LocalP  int
	Remote  net.IP
	RemoteP int
	State   TCPState
	Inode   uint64
	UID     uint32
}

// ReadNetSockets parses every TCP/UDP (v4+v6) row from /proc/net/*.
func ReadNetSockets() ([]SocketRow, error) {
	var out []SocketRow
	for _, p := range []string{
		"/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6",
	} {
		rows, err := readSocketFile(p)
		if err != nil {
			continue
		}
		out = append(out, rows...)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no socket data (non-linux host?)")
	}
	return out, nil
}

func readSocketFile(path string) ([]SocketRow, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	proto := "tcp"
	switch path {
	case "/proc/net/tcp6":
		proto = "tcp6"
	case "/proc/net/udp":
		proto = "udp"
	case "/proc/net/udp6":
		proto = "udp6"
	}
	var out []SocketRow
	sc := bufio.NewScanner(f)
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue
		}
		row, err := parseSocketLine(proto, sc.Text())
		if err != nil {
			continue
		}
		out = append(out, row)
	}
	return out, sc.Err()
}

// parseSocketLine: columns are
//   sl local_address rem_address st tx_queue:rx_queue tr:tm->when retrnsmt uid timeout inode ...
func parseSocketLine(proto, line string) (SocketRow, error) {
	fields := strings.Fields(line)
	if len(fields) < 10 {
		return SocketRow{}, fmt.Errorf("too short")
	}
	local := fields[1]
	remote := fields[2]
	state := fields[3]
	uidStr := fields[7]
	inodeStr := fields[9]

	lip, lp, err := parseHexAddr(local)
	if err != nil {
		return SocketRow{}, err
	}
	rip, rp, err := parseHexAddr(remote)
	if err != nil {
		return SocketRow{}, err
	}
	stv, err := strconv.ParseUint(state, 16, 8)
	if err != nil {
		return SocketRow{}, err
	}
	uid64, _ := strconv.ParseUint(uidStr, 10, 32)
	inode, _ := strconv.ParseUint(inodeStr, 10, 64)
	return SocketRow{
		Proto:   proto,
		Local:   lip,
		LocalP:  lp,
		Remote:  rip,
		RemoteP: rp,
		State:   TCPState(stv),
		Inode:   inode,
		UID:     uint32(uid64),
	}, nil
}

// parseHexAddr decodes "01020A0B:1F90" into 10.11.2.1 and port 8080.
// /proc/net/tcp uses host-byte-order little-endian 32-bit groups per u32
// word for both IPv4 and IPv6.
func parseHexAddr(s string) (net.IP, int, error) {
	i := strings.IndexByte(s, ':')
	if i < 0 {
		return nil, 0, fmt.Errorf("no port")
	}
	addrHex := s[:i]
	portHex := s[i+1:]
	port, err := strconv.ParseInt(portHex, 16, 32)
	if err != nil {
		return nil, 0, err
	}
	raw, err := hex.DecodeString(addrHex)
	if err != nil {
		return nil, 0, err
	}
	switch len(raw) {
	case 4:
		return net.IPv4(raw[3], raw[2], raw[1], raw[0]).To4(), int(port), nil
	case 16:
		ip := make(net.IP, 16)
		for w := 0; w < 4; w++ {
			ip[w*4+0] = raw[w*4+3]
			ip[w*4+1] = raw[w*4+2]
			ip[w*4+2] = raw[w*4+1]
			ip[w*4+3] = raw[w*4+0]
		}
		return ip, int(port), nil
	default:
		return nil, 0, fmt.Errorf("bad addr length %d", len(raw))
	}
}

// SocketInodes returns the set of socket inode numbers owned by pid
// (via scanning /proc/pid/fd symlinks that point at "socket:[INODE]").
func SocketInodes(pid int) (map[uint64]struct{}, error) {
	base := fmt.Sprintf("/proc/%d/fd", pid)
	entries, err := os.ReadDir(base)
	if err != nil {
		return nil, err
	}
	out := make(map[uint64]struct{}, len(entries))
	for _, e := range entries {
		target, err := os.Readlink(base + "/" + e.Name())
		if err != nil {
			continue
		}
		if !strings.HasPrefix(target, "socket:[") {
			continue
		}
		inodeStr := strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")
		if v, err := strconv.ParseUint(inodeStr, 10, 64); err == nil {
			out[v] = struct{}{}
		}
	}
	return out, nil
}

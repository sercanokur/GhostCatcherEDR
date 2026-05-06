package syslog

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"ghostcatcher/internal/event"
)

// Default UDP payload cap for SIEM listeners (many cap at 8 KiB).
const defaultMaxMsg = 8192

var facilityByName = map[string]int{
	"kern":     0,
	"user":     1,
	"mail":     2,
	"daemon":   3,
	"auth":     4,
	"syslog":   5,
	"lpr":      6,
	"news":     7,
	"uucp":     8,
	"cron":     9,
	"authpriv": 10,
	"ftp":      11,
	"local0":   16,
	"local1":   17,
	"local2":   18,
	"local3":   19,
	"local4":   20,
	"local5":   21,
	"local6":   22,
	"local7":   23,
}

// Config drives UDP syslog framing (RFC5424 or legacy RFC3164-style).
type Config struct {
	Enabled     bool
	Host        string
	Port        int
	Format      string // rfc5424 | rfc3164
	Facility    string // name or 0-23
	AppName     string
	Hostname    string // syslog header hostname; empty = os.Hostname()
	ProcID      string // RFC5424 PROCID; empty = "-"
	MaxMsgBytes int
}

// Client holds a single UDP association to the SIEM collector.
type Client struct {
	cfg  Config
	conn *net.UDPConn
	host string
	pid  int
}

// NewUDP builds a client; does not send yet. host must resolve for Send to work.
func NewUDP(cfg Config) (*Client, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	if cfg.Host == "" {
		return nil, fmt.Errorf("syslog_udp: host required when enabled")
	}
	if cfg.Port <= 0 || cfg.Port > 65535 {
		return nil, fmt.Errorf("syslog_udp: port must be 1-65535")
	}
	f := strings.ToLower(strings.TrimSpace(cfg.Format))
	if f == "" {
		f = "rfc5424"
	}
	if f != "rfc5424" && f != "rfc3164" {
		return nil, fmt.Errorf("syslog_udp: format must be rfc5424 or rfc3164")
	}
	cfg.Format = f

	if cfg.MaxMsgBytes <= 0 {
		cfg.MaxMsgBytes = defaultMaxMsg
	}
	if cfg.AppName == "" {
		cfg.AppName = "ghostcatcher"
	}
	hn := cfg.Hostname
	if hn == "" {
		var err error
		hn, err = os.Hostname()
		if err != nil {
			hn = "localhost"
		}
	}
	cfg.Hostname = hn

	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port)))
	if err != nil {
		return nil, fmt.Errorf("syslog_udp resolve: %w", err)
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil, fmt.Errorf("syslog_udp dial: %w", err)
	}
	return &Client{cfg: cfg, conn: conn, host: cfg.Hostname, pid: os.Getpid()}, nil
}

// Send formats the event as syslog and writes one UDP packet.
func (c *Client) Send(ev *event.Event, jsonLine []byte) error {
	if c == nil {
		return nil
	}
	fac, err := parseFacility(c.cfg.Facility)
	if err != nil {
		return err
	}
	sev := severityToSyslog(ev.Severity)
	pri := fac*8 + sev

	msg := trimToMax(jsonLine, c.cfg.MaxMsgBytes)
	var line string
	switch c.cfg.Format {
	case "rfc3164":
		line = formatRFC3164(pri, time.Now().UTC(), c.host, c.cfg.AppName, string(msg))
	default:
		msgID := ev.RuleID
		if msgID == "" {
			msgID = "-"
		} else if strings.ContainsAny(msgID, " \t]") {
			msgID = "-"
		}
		procID := c.cfg.ProcID
		if procID == "" {
			procID = strconv.Itoa(c.pid)
		}
		line = formatRFC5424(pri, ev.Timestamp.UTC(), c.host, c.cfg.AppName, procID, msgID, string(msg))
	}
	_, err = c.conn.Write([]byte(line))
	return err
}

func parseFacility(s string) (int, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return facilityByName["local0"], nil
	}
	if v, ok := facilityByName[s]; ok {
		return v, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 || n > 23 {
		return 0, fmt.Errorf("syslog_udp: invalid facility %q (use local0-local7 or 0-23)", s)
	}
	return n, nil
}

func severityToSyslog(s event.Severity) int {
	switch s {
	case event.SeverityCritical:
		return 2 // critical
	case event.SeverityHigh:
		return 3 // err
	case event.SeverityMedium:
		return 4 // warning
	case event.SeverityLow:
		return 5 // notice
	default:
		return 6 // informational
	}
}

// formatRFC5424: HEADER SP STRUCTURED-DATA SP MSG
func formatRFC5424(pri int, ts time.Time, hostname, app, procID, msgID, msg string) string {
	tsStr := ts.Format("2006-01-02T15:04:05.000Z")
	return fmt.Sprintf("<%d>1 %s %s %s %s %s - %s", pri, tsStr, hostname, app, procID, msgID, msg)
}

func formatRFC3164(pri int, ts time.Time, hostname, tag, msg string) string {
	tsStr := ts.Format("Jan 2 15:04:05")
	return fmt.Sprintf("<%d>%s %s %s: %s", pri, tsStr, hostname, tag, msg)
}

func trimToMax(b []byte, max int) []byte {
	if max <= 0 || len(b) <= max {
		return b
	}
	out := make([]byte, max)
	copy(out, b)
	return out
}

// Package syslogtcp streams events over RFC5424 syslog/TCP, optionally
// wrapped in TLS. It is intended for enterprise SIEM collectors that
// prefer TCP over the lossy UDP path.
package syslogtcp

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"ghostcatcher/internal/event"
)

type Config struct {
	Enabled       bool
	Host          string
	Port          int
	TLS           bool
	TLSCACertFile string
	TLSServerName string
	AppName       string
	Hostname      string
	ProcID        string
	Facility      string
	MaxMsgBytes   int
}

type Client struct {
	cfg  Config
	mu   sync.Mutex
	conn net.Conn
}

func New(cfg Config) (*Client, error) {
	if !cfg.Enabled {
		return nil, errors.New("syslogtcp: disabled")
	}
	if cfg.AppName == "" {
		cfg.AppName = "ghostcatcher"
	}
	if cfg.Hostname == "" {
		host, _ := os.Hostname()
		cfg.Hostname = host
	}
	if cfg.ProcID == "" {
		cfg.ProcID = strconv.Itoa(os.Getpid())
	}
	if cfg.MaxMsgBytes == 0 {
		cfg.MaxMsgBytes = 8192
	}
	return &Client{cfg: cfg}, nil
}

func (c *Client) Name() string { return "syslog-tcp" }

func (c *Client) dial() (net.Conn, error) {
	addr := net.JoinHostPort(c.cfg.Host, strconv.Itoa(c.cfg.Port))
	d := net.Dialer{Timeout: 5 * time.Second}
	if !c.cfg.TLS {
		return d.Dial("tcp", addr)
	}
	tc := &tls.Config{ServerName: c.cfg.TLSServerName}
	if c.cfg.TLSCACertFile != "" {
		pem, err := os.ReadFile(c.cfg.TLSCACertFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("syslogtcp: failed to load CA cert")
		}
		tc.RootCAs = pool
	}
	return tls.DialWithDialer(&d, "tcp", addr, tc)
}

// Send retries once on transport error to tolerate brief disconnects.
func (c *Client) Send(ctx context.Context, e *event.Event, raw []byte) error {
	framed := c.frame(e, raw)
	c.mu.Lock()
	defer c.mu.Unlock()
	for attempt := 0; attempt < 2; attempt++ {
		if c.conn == nil {
			conn, err := c.dial()
			if err != nil {
				return fmt.Errorf("dial: %w", err)
			}
			c.conn = conn
		}
		deadline, ok := ctx.Deadline()
		if !ok {
			deadline = time.Now().Add(5 * time.Second)
		}
		_ = c.conn.SetWriteDeadline(deadline)
		if _, err := c.conn.Write(framed); err != nil {
			_ = c.conn.Close()
			c.conn = nil
			if attempt == 0 {
				continue
			}
			return err
		}
		return nil
	}
	return errors.New("syslogtcp: exhausted retries")
}

func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		err := c.conn.Close()
		c.conn = nil
		return err
	}
	return nil
}

// frame builds an RFC5425 octet-counted RFC5424 message. This is the
// format Splunk, rsyslog, and syslog-ng accept out of the box.
func (c *Client) frame(e *event.Event, raw []byte) []byte {
	pri := 13*8 + 5 // local5 + notice
	ts := e.Timestamp.UTC().Format("2006-01-02T15:04:05Z")
	msgID := e.RuleID
	if msgID == "" {
		msgID = "-"
	}
	msg := fmt.Sprintf("<%d>1 %s %s %s %s %s - %s",
		pri, ts, c.cfg.Hostname, c.cfg.AppName, c.cfg.ProcID, msgID, string(raw))
	if len(msg) > c.cfg.MaxMsgBytes {
		msg = msg[:c.cfg.MaxMsgBytes]
	}
	// Octet-counted framing per RFC 5425.
	var out bytes.Buffer
	fmt.Fprintf(&out, "%d %s", len(msg), strings.TrimRight(msg, "\r\n"))
	return out.Bytes()
}

// Package loki ships events to Grafana Loki via the /loki/api/v1/push
// endpoint. Each event becomes a log line with labels merged from the
// configured static map.
package loki

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"ghostcatcher/internal/event"
)

type Config struct {
	Enabled  bool
	URL      string
	Labels   map[string]string
	Username string
	Password string
	Insecure bool
}

type Client struct {
	cfg Config
	h   *http.Client
}

func New(cfg Config) (*Client, error) {
	if !cfg.Enabled {
		return nil, errors.New("loki: disabled")
	}
	if cfg.URL == "" {
		return nil, errors.New("loki: url required")
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.Insecure}}
	return &Client{cfg: cfg, h: &http.Client{Transport: tr, Timeout: 10 * time.Second}}, nil
}

func (c *Client) Name() string { return "loki" }

type pushPayload struct {
	Streams []pushStream `json:"streams"`
}
type pushStream struct {
	Stream map[string]string `json:"stream"`
	Values [][2]string       `json:"values"`
}

func (c *Client) Send(ctx context.Context, e *event.Event, raw []byte) error {
	labels := map[string]string{"app": "ghostcatcher"}
	for k, v := range c.cfg.Labels {
		labels[k] = v
	}
	if e.RuleID != "" {
		labels["rule_id"] = e.RuleID
	}
	if e.Severity != "" {
		labels["severity"] = string(e.Severity)
	}
	ts := fmt.Sprintf("%d", e.Timestamp.UnixNano())
	payload := pushPayload{Streams: []pushStream{{
		Stream: labels,
		Values: [][2]string{{ts, string(raw)}},
	}}}
	b, _ := json.Marshal(payload)
	url := strings.TrimRight(c.cfg.URL, "/") + "/loki/api/v1/push"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.cfg.Username != "" && c.cfg.Password != "" {
		cred := base64.StdEncoding.EncodeToString([]byte(c.cfg.Username + ":" + c.cfg.Password))
		req.Header.Set("Authorization", "Basic "+cred)
	}
	resp, err := c.h.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("loki push status %d", resp.StatusCode)
	}
	return nil
}

func (c *Client) Close() error { return nil }

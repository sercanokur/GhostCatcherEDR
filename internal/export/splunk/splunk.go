// Package splunk posts events to the Splunk HTTP Event Collector (HEC).
// The payload format is {"event": <raw json>, "sourcetype": ..., "index": ...}.
package splunk

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"ghostcatcher/internal/event"
)

type Config struct {
	Enabled    bool
	URL        string
	Token      string
	Index      string
	SourceType string
	Insecure   bool
}

type Client struct {
	cfg Config
	h   *http.Client
}

func New(cfg Config) (*Client, error) {
	if !cfg.Enabled {
		return nil, errors.New("splunk: disabled")
	}
	if cfg.URL == "" || cfg.Token == "" {
		return nil, errors.New("splunk: url and token required")
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.Insecure}}
	return &Client{cfg: cfg, h: &http.Client{Transport: tr, Timeout: 10 * time.Second}}, nil
}

func (c *Client) Name() string { return "splunk-hec" }

func (c *Client) Send(ctx context.Context, e *event.Event, raw []byte) error {
	body := map[string]interface{}{"event": json.RawMessage(raw)}
	if c.cfg.Index != "" {
		body["index"] = c.cfg.Index
	}
	if c.cfg.SourceType != "" {
		body["sourcetype"] = c.cfg.SourceType
	}
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.URL, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Splunk "+c.cfg.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.h.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("splunk hec status %d", resp.StatusCode)
	}
	_ = e
	return nil
}

func (c *Client) Close() error { return nil }

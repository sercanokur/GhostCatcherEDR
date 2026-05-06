// Package elastic ships events to Elasticsearch's _bulk endpoint.
package elastic

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
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
	Index    string
	APIKey   string
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
		return nil, errors.New("elastic: disabled")
	}
	if cfg.URL == "" || cfg.Index == "" {
		return nil, errors.New("elastic: url and index required")
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.Insecure}}
	return &Client{cfg: cfg, h: &http.Client{Transport: tr, Timeout: 10 * time.Second}}, nil
}

func (c *Client) Name() string { return "elastic-bulk" }

func (c *Client) Send(ctx context.Context, _ *event.Event, raw []byte) error {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, `{"index":{"_index":%q}}`+"\n", c.cfg.Index)
	buf.Write(raw)
	buf.WriteByte('\n')

	url := strings.TrimRight(c.cfg.URL, "/") + "/_bulk"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	switch {
	case c.cfg.APIKey != "":
		req.Header.Set("Authorization", "ApiKey "+c.cfg.APIKey)
	case c.cfg.Username != "" && c.cfg.Password != "":
		cred := base64.StdEncoding.EncodeToString([]byte(c.cfg.Username + ":" + c.cfg.Password))
		req.Header.Set("Authorization", "Basic "+cred)
	}
	resp, err := c.h.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("elastic bulk status %d", resp.StatusCode)
	}
	return nil
}

func (c *Client) Close() error { return nil }

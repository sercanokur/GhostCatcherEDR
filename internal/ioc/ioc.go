// Package ioc loads flat-file indicator-of-compromise lists (hashes, IPs,
// domains) that detectors can consult to bump confidence on a match.
//
// Feeds are simple one-indicator-per-line text files. Lines starting with
// "#" or empty lines are ignored, so upstream feed commentary is tolerated.
// Values are stored case-insensitively where appropriate.
package ioc

import (
	"bufio"
	"net"
	"os"
	"strings"
	"sync"
)

// Feed is an in-memory set of indicators. Safe for concurrent reads after
// Load; writes happen only during Load.
type Feed struct {
	mu      sync.RWMutex
	hashes  map[string]struct{}
	ips     map[string]struct{}
	cidrs   []*net.IPNet
	domains map[string]struct{}
}

// NewFeed returns an empty, safely-usable Feed.
func NewFeed() *Feed {
	return &Feed{
		hashes:  map[string]struct{}{},
		ips:     map[string]struct{}{},
		domains: map[string]struct{}{},
	}
}

// Load ingests each file into the appropriate bucket. Unknown file types
// are inferred from contents line by line (hash lengths of 32/40/64 chars,
// IP via net.ParseIP, anything else treated as domain).
func (f *Feed) Load(hashFiles, ipFiles, domainFiles []string) error {
	for _, p := range hashFiles {
		if err := f.loadInto(p, f.addHash); err != nil {
			return err
		}
	}
	for _, p := range ipFiles {
		if err := f.loadInto(p, f.addIP); err != nil {
			return err
		}
	}
	for _, p := range domainFiles {
		if err := f.loadInto(p, f.addDomain); err != nil {
			return err
		}
	}
	return nil
}

func (f *Feed) loadInto(path string, add func(string)) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	sc := bufio.NewScanner(file)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		add(line)
	}
	return sc.Err()
}

func (f *Feed) addHash(v string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hashes[strings.ToLower(strings.TrimSpace(v))] = struct{}{}
}

func (f *Feed) addIP(v string) {
	v = strings.TrimSpace(v)
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, n, err := net.ParseCIDR(v); err == nil {
		f.cidrs = append(f.cidrs, n)
		return
	}
	if ip := net.ParseIP(v); ip != nil {
		f.ips[ip.String()] = struct{}{}
		return
	}
}

func (f *Feed) addDomain(v string) {
	v = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(v, ".")))
	f.mu.Lock()
	defer f.mu.Unlock()
	f.domains[v] = struct{}{}
}

// MatchHash returns true when h is present in the feed (hex, case-insensitive).
func (f *Feed) MatchHash(h string) bool {
	if f == nil {
		return false
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	_, ok := f.hashes[strings.ToLower(strings.TrimSpace(h))]
	return ok
}

// MatchIP returns true when ip is present as an exact match or falls within
// a CIDR loaded from the feed files.
func (f *Feed) MatchIP(ip net.IP) bool {
	if f == nil || ip == nil {
		return false
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	if _, ok := f.ips[ip.String()]; ok {
		return true
	}
	for _, n := range f.cidrs {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// MatchDomain performs an exact match plus any-label suffix match so that
// a feed entry "evil.example" matches "sub.evil.example".
func (f *Feed) MatchDomain(d string) bool {
	if f == nil || d == "" {
		return false
	}
	d = strings.ToLower(strings.TrimSpace(d))
	f.mu.RLock()
	defer f.mu.RUnlock()
	if _, ok := f.domains[d]; ok {
		return true
	}
	for suffix := range f.domains {
		if strings.HasSuffix(d, "."+suffix) {
			return true
		}
	}
	return false
}

// Sizes returns the loaded indicator counts (for boot diagnostics).
func (f *Feed) Sizes() (hashes, ips, cidrs, domains int) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return len(f.hashes), len(f.ips), len(f.cidrs), len(f.domains)
}

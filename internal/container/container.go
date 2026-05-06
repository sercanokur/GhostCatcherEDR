// Package container derives a short container id + runtime label from a
// /proc/pid/cgroup snapshot so events can be tagged with container context
// instead of raw host pids.
package container

import (
	"regexp"
	"strings"
)

// Info is the minimal container fingerprint the agent embeds in events.
type Info struct {
	Runtime string // docker | containerd | cri-o | k8s | lxc
	ID      string // 12-char short id
	PodUID  string // kubernetes pod UID if derivable
}

// dockerIDRE pulls a 64-char hex id out of cgroup path fragments like:
//   12:freezer:/docker/5f2cd1b0...
//   0::/system.slice/docker-5f2cd1b0.scope
var dockerIDRE = regexp.MustCompile(`[0-9a-f]{64}`)

// k8sPodUIDRE captures the pod UID from kubelet cgroup paths. Kubelet
// writes UIDs with either dashes (plain mode) or underscores (systemd mode),
// so both separators are accepted.
var k8sPodUIDRE = regexp.MustCompile(`pod([0-9a-fA-F]{8}[-_]?[0-9a-fA-F]{4}[-_]?[0-9a-fA-F]{4}[-_]?[0-9a-fA-F]{4}[-_]?[0-9a-fA-F]{12})`)

// Classify maps a /proc/pid/cgroup payload to an Info. Empty/blank input or
// purely host cgroups (no container markers) returns an empty Info.
func Classify(cgroup string) Info {
	if cgroup == "" {
		return Info{}
	}
	low := strings.ToLower(cgroup)
	var info Info

	switch {
	case strings.Contains(low, "/docker/") || strings.Contains(low, "docker-") || strings.Contains(low, "/docker-"):
		info.Runtime = "docker"
	case strings.Contains(low, "/containerd/") || strings.Contains(low, "cri-containerd") || strings.Contains(low, "containerd-"):
		info.Runtime = "containerd"
	case strings.Contains(low, "cri-o") || strings.Contains(low, "crio-"):
		info.Runtime = "cri-o"
	case strings.Contains(low, "/lxc/") || strings.Contains(low, "lxc.payload."):
		info.Runtime = "lxc"
	case strings.Contains(low, "kubepods"):
		info.Runtime = "k8s"
	}

	if m := dockerIDRE.FindString(cgroup); m != "" {
		if len(m) >= 12 {
			info.ID = m[:12]
		} else {
			info.ID = m
		}
	}
	if m := k8sPodUIDRE.FindStringSubmatch(cgroup); len(m) >= 2 {
		info.PodUID = m[1]
		if info.Runtime == "" {
			info.Runtime = "k8s"
		}
	}
	return info
}

// IsZero reports whether the info carries no useful classification.
func (i Info) IsZero() bool { return i.Runtime == "" && i.ID == "" && i.PodUID == "" }

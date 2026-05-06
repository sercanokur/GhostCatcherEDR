package persistence

import (
	"path/filepath"
)

// AuthorizedKeysPaths returns paths to ~/.ssh/authorized_keys for interactive users (for fsnotify watches).
func AuthorizedKeysPaths() ([]string, error) {
	users, err := passwdUsers()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, u := range users {
		if u.dir == "" || u.shell == "/usr/sbin/nologin" || u.shell == "/bin/false" {
			continue
		}
		p := filepath.Join(u.dir, ".ssh", "authorized_keys")
		out = append(out, p)
	}
	return out, nil
}

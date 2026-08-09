package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

type sshClient struct {
	client *ssh.Client
	target string
}

func dialSSH(target, keyPath string) (*sshClient, error) {
	user, host := "root", target
	if i := strings.IndexByte(target, '@'); i >= 0 {
		user = target[:i]
		host = target[i+1:]
	}
	if !strings.Contains(host, ":") {
		host = net.JoinHostPort(host, "22")
	}

	keyPath = expandHome(keyPath)
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read ssh key %s: %w", keyPath, err)
	}
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("parse ssh key: %w", err)
	}

	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // lab only
		Timeout:         20 * time.Second,
	}
	c, err := ssh.Dial("tcp", host, cfg)
	if err != nil {
		return nil, fmt.Errorf("ssh dial %s: %w", host, err)
	}
	return &sshClient{client: c, target: target}, nil
}

func (s *sshClient) Close() error {
	if s == nil || s.client == nil {
		return nil
	}
	return s.client.Close()
}

func (s *sshClient) Run(cmd string) (string, error) {
	return s.RunStream(cmd, nil)
}

func (s *sshClient) RunStream(cmd string, stream io.Writer) (string, error) {
	sess, err := s.client.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()

	var buf bytes.Buffer
	var w io.Writer = &buf
	if stream != nil {
		w = io.MultiWriter(&buf, stream)
	}
	sess.Stdout = w
	sess.Stderr = w
	err = sess.Run(cmd)
	return buf.String(), err
}

func expandHome(p string) string {
	if strings.HasPrefix(p, "~/") {
		home, err := os.UserHomeDir()
		if err == nil {
			return filepath.Join(home, p[2:])
		}
	}
	return p
}

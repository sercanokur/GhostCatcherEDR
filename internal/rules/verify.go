package rules

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
)

// VerifyPackSignature checks that sigPath contains a valid detached ed25519
// signature over packPath. We intentionally support a very small sig format
// so operators can generate it with one-liners:
//
//	$ openssl pkey -in priv.pem -noout -text  # ed25519 priv/pub
//	$ openssl pkeyutl -sign -inkey priv.pem -rawin -in pack.yaml \
//	    | base64 > pack.yaml.sig
//
// The pubkey is read from the path provided in configuration; it is the
// 32-byte raw public key, base64-encoded, optionally prefixed by
// "ed25519:" so operators can distinguish key algorithms in a shared
// file.
func VerifyPackSignature(packPath, sigPath, pubKeyPath string) error {
	if pubKeyPath == "" {
		return errors.New("rules: no public key configured; refusing to verify")
	}
	pub, err := loadEd25519Pub(pubKeyPath)
	if err != nil {
		return fmt.Errorf("load pubkey: %w", err)
	}
	msg, err := os.ReadFile(packPath)
	if err != nil {
		return err
	}
	sigRaw, err := os.ReadFile(sigPath)
	if err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigRaw)))
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	if !ed25519.Verify(pub, msg, sig) {
		return errors.New("rules: signature verification failed")
	}
	return nil
}

func loadEd25519Pub(path string) (ed25519.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	s := strings.TrimSpace(string(raw))
	s = strings.TrimPrefix(s, "ed25519:")
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("decode pubkey: %w", err)
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("unexpected pubkey size %d", len(b))
	}
	return ed25519.PublicKey(b), nil
}

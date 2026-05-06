package web

import (
	"encoding/base64"
	"math"
	"os"
	"regexp"
	"strings"
	"syscall"
)

// normalizeSource strips comments, collapses whitespace, removes noise that
// hides behaviour from pattern matchers (string concatenation, hex/chr
// assembly) so the regex set in patterns.go sees the "resolved" shape of
// a payload.
//
// The resulting string MUST only be used for pattern matching; evidence
// snippets are still drawn from the original.
func normalizeSource(src string) string {
	s := src
	s = stripPHPComments(s)
	s = collapseStringConcat(s)
	s = decodeInlineBase64(s)
	s = strings.ReplaceAll(s, "\t", " ")
	s = multiSpace.ReplaceAllString(s, " ")
	return s
}

var multiSpace = regexp.MustCompile(`[ ]{2,}`)

// stripPHPComments removes // line, # line, and /* ... */ block comments.
// It is intentionally PHP-flavored; scripts that smuggle payloads inside
// /*!50001 ... */ hints or # comments are already suspicious.
func stripPHPComments(s string) string {
	s = lineCommentRE.ReplaceAllString(s, "")
	s = hashCommentRE.ReplaceAllString(s, "")
	s = blockCommentRE.ReplaceAllString(s, " ")
	return s
}

var (
	lineCommentRE  = regexp.MustCompile(`//[^\n]*`)
	hashCommentRE  = regexp.MustCompile(`(?m)(^|\s)#[^\n]*`)
	blockCommentRE = regexp.MustCompile(`(?s)/\*.*?\*/`)
)

// collapseStringConcat turns `"ev"."al"` into `"eval"` (and similar) so
// concatenation-based obfuscation of sink names cannot hide from regexes.
// Applied iteratively until the source stops shrinking.
func collapseStringConcat(s string) string {
	for i := 0; i < 8; i++ {
		out := concatRE.ReplaceAllString(s, `"${1}${2}"`)
		if out == s {
			break
		}
		s = out
	}
	return s
}

var concatRE = regexp.MustCompile(`"([^"\\\n]{0,128})"\s*\.\s*"([^"\\\n]{0,128})"`)

// decodeInlineBase64 decodes short base64 blobs back to plaintext if the
// decoded contents look shell-ish. Long blobs are left alone because the
// long_base64_blob pattern handles those; we only target compact payloads
// that evade the length threshold.
func decodeInlineBase64(s string) string {
	return shortB64RE.ReplaceAllStringFunc(s, func(m string) string {
		dec, err := base64.StdEncoding.DecodeString(strings.Trim(m, "\"'"))
		if err != nil {
			return m
		}
		if !containsShellLikely(string(dec)) {
			return m
		}
		return m + " /*<decoded>*/ " + string(dec)
	})
}

var shortB64RE = regexp.MustCompile(`["'][A-Za-z0-9+/]{16,118}={0,2}["']`)

func containsShellLikely(s string) bool {
	low := strings.ToLower(s)
	for _, needle := range []string{"eval", "system", "exec", "passthru", "bash", "/bin/", "wget", "curl", "python -c", "whoami"} {
		if strings.Contains(low, needle) {
			return true
		}
	}
	return false
}

// shannonEntropy returns 0..8 bits per byte for the input. Values above 7.5
// on a mostly ASCII file imply heavy encoding/compression/encryption - a
// strong single-signal webshell hint.
func shannonEntropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var counts [256]float64
	for _, c := range b {
		counts[c]++
	}
	n := float64(len(b))
	var h float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := c / n
		h -= p * math.Log2(p)
	}
	return h
}

// magicByteMismatch reports true when the file's first bytes do not match
// the script-opening conventions for its extension (e.g. a .jpg that starts
// with <?php, or a .php file that starts with MZ/ELF bytes).
//
// It only returns true when the mismatch is a credible web-shell polyglot,
// not for benign text assets that happen to lack a magic number.
func magicByteMismatch(path string, data []byte) bool {
	if len(data) < 4 {
		return false
	}
	head := data[:minInt(16, len(data))]
	ext := strings.ToLower(path)

	phpLike := strings.HasSuffix(ext, ".php") || strings.HasSuffix(ext, ".phtml") ||
		strings.HasSuffix(ext, ".phar") || strings.HasSuffix(ext, ".inc")

	startsPHP := bytesStartsWithAny(head, []byte("<?php"), []byte("<?="), []byte("<?\n"), []byte("<? "), []byte("<?\t"), []byte("<?xml"))
	startsELF := len(head) >= 4 && head[0] == 0x7f && head[1] == 'E' && head[2] == 'L' && head[3] == 'F'
	startsMZ := len(head) >= 2 && head[0] == 'M' && head[1] == 'Z'
	startsJPEG := len(head) >= 3 && head[0] == 0xff && head[1] == 0xd8 && head[2] == 0xff
	startsPNG := len(head) >= 4 && head[0] == 0x89 && head[1] == 'P' && head[2] == 'N' && head[3] == 'G'
	startsGIF := strings.HasPrefix(string(head), "GIF8")

	// ELF/MZ inside a script file is almost always packed malware.
	if phpLike && (startsELF || startsMZ) {
		return true
	}
	// Image-shaped file that contains PHP tags after the magic = polyglot.
	if (startsJPEG || startsPNG || startsGIF) && strings.Contains(string(data), "<?php") {
		return true
	}
	// File named as image/log/txt but starts with a PHP tag.
	hiddenPHP := startsPHP && !phpLike &&
		(strings.HasSuffix(ext, ".jpg") || strings.HasSuffix(ext, ".jpeg") ||
			strings.HasSuffix(ext, ".png") || strings.HasSuffix(ext, ".gif") ||
			strings.HasSuffix(ext, ".txt") || strings.HasSuffix(ext, ".log") ||
			strings.HasSuffix(ext, ".ico") || strings.HasSuffix(ext, ".css") ||
			strings.HasSuffix(ext, ".js") || strings.HasSuffix(ext, ".html"))
	return hiddenPHP
}

func bytesStartsWithAny(b []byte, prefixes ...[]byte) bool {
	for _, p := range prefixes {
		if len(b) >= len(p) {
			match := true
			for i := range p {
				if b[i] != p[i] {
					match = false
					break
				}
			}
			if match {
				return true
			}
		}
	}
	return false
}

// fileAttributes gathers host-side ownership/mode flags that are cheap to
// compute and valuable as independent corroborating signals.
type fileAttributes struct {
	SetUID bool
	SetGID bool
	OwnerUID uint32
	Mode os.FileMode
}

func readFileAttributes(fi os.FileInfo) fileAttributes {
	fa := fileAttributes{
		Mode: fi.Mode(),
	}
	fa.SetUID = fi.Mode()&os.ModeSetuid != 0
	fa.SetGID = fi.Mode()&os.ModeSetgid != 0
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		fa.OwnerUID = uint32(st.Uid)
	}
	return fa
}

// hasSuspiciousExtension is a helper used by file walkers.
func hasSuspiciousExtension(path string) bool {
	low := strings.ToLower(path)
	for _, e := range suspiciousExtensions {
		if strings.HasSuffix(low, e) {
			return true
		}
	}
	return false
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

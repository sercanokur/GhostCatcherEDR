package web

import (
	"strings"
	"unicode"
)

// phpTokenKind classifies a lexed PHP token. We do not implement a full
// PHP grammar — just enough tokens (`<?php`, identifier, string, paren,
// special superglobals) to detect a tainted-source → dangerous-sink flow
// inside a single file. This catches the overwhelming majority of real
// world web shells which are compact and single-file by design.
type phpTokenKind int

const (
	phpTokOpen phpTokenKind = iota
	phpTokIdent
	phpTokVar
	phpTokString
	phpTokPunct
	phpTokNumber
	phpTokOther
)

type phpToken struct {
	kind  phpTokenKind
	value string
}

// dangerousSinks are call targets whose execution of tainted data causes
// RCE. The set is broad on purpose; IDS coverage matters more than
// false-positive rate here because the detector emits a per-file signal
// which is then combined with baseline+entropy+magicbyte checks.
var dangerousSinks = map[string]struct{}{
	"eval": {}, "assert": {}, "create_function": {},
	"system": {}, "exec": {}, "passthru": {}, "shell_exec": {},
	"proc_open": {}, "popen": {}, "pcntl_exec": {},
	"preg_replace": {}, // /e modifier
	"include": {}, "include_once": {}, "require": {}, "require_once": {},
	"file_get_contents": {}, "file_put_contents": {}, "fwrite": {},
}

// taintedSources are PHP superglobals that carry attacker-controlled data.
var taintedSources = map[string]struct{}{
	"_GET": {}, "_POST": {}, "_REQUEST": {}, "_COOKIE": {},
	"_SERVER": {}, "_FILES": {}, "_ENV": {},
	"HTTP_RAW_POST_DATA": {}, "php://input": {},
}

// scanPHPTaintFlow returns true iff any dangerous sink in src receives a
// value that flows from a tainted source in the same file. The detector
// is intraprocedural and conservative: if it cannot tell, it returns
// false so the caller does not escalate.
func scanPHPTaintFlow(src string) (bool, string) {
	if !strings.Contains(src, "<?") {
		return false, ""
	}
	toks := tokenizePHP(src)
	if len(toks) == 0 {
		return false, ""
	}
	// Build a simple variable → is_tainted map by walking left to right.
	// $x = $_GET['a']           -> tainted[$x] = true
	// $x = base64_decode($x)    -> taint propagates
	// $x = "foo"                -> tainted[$x] = false
	tainted := map[string]bool{}
	// Track which tainted-originating identifiers flow into sinks.
	for i := 0; i < len(toks); i++ {
		t := toks[i]
		// tainted assignment: $x = ... <source> ...
		if t.kind == phpTokVar && i+2 < len(toks) &&
			toks[i+1].kind == phpTokPunct && toks[i+1].value == "=" {
			rhs := sliceRHS(toks, i+2)
			if rhsUsesTaint(rhs, tainted) {
				tainted[t.value] = true
			} else if rhsAllLiteral(rhs) {
				// Explicit sanitization to literal breaks taint.
				tainted[t.value] = false
			}
			continue
		}
		// sink call: ident '(' ...
		if t.kind == phpTokIdent && i+1 < len(toks) && toks[i+1].value == "(" {
			name := t.value
			if _, hit := dangerousSinks[name]; !hit {
				continue
			}
			args := sliceCallArgs(toks, i+2)
			if rhsUsesTaint(args, tainted) {
				return true, name
			}
		}
	}
	return false, ""
}

func sliceRHS(toks []phpToken, from int) []phpToken {
	for i := from; i < len(toks); i++ {
		if toks[i].kind == phpTokPunct && (toks[i].value == ";" || toks[i].value == "\n") {
			return toks[from:i]
		}
	}
	return toks[from:]
}

func sliceCallArgs(toks []phpToken, from int) []phpToken {
	depth := 1
	for i := from; i < len(toks); i++ {
		if toks[i].value == "(" {
			depth++
		} else if toks[i].value == ")" {
			depth--
			if depth == 0 {
				return toks[from:i]
			}
		}
	}
	return toks[from:]
}

func rhsUsesTaint(toks []phpToken, tainted map[string]bool) bool {
	for _, t := range toks {
		if t.kind == phpTokVar {
			if tainted[t.value] {
				return true
			}
			// Strip leading '$' to compare against superglobal names.
			name := strings.TrimPrefix(t.value, "$")
			if _, src := taintedSources[name]; src {
				return true
			}
		}
		if t.kind == phpTokIdent {
			if _, src := taintedSources[t.value]; src {
				return true
			}
		}
		if t.kind == phpTokString {
			s := t.value
			if _, src := taintedSources[s]; src {
				return true
			}
			if strings.HasPrefix(s, "php://input") {
				return true
			}
		}
	}
	return false
}

func rhsAllLiteral(toks []phpToken) bool {
	for _, t := range toks {
		if t.kind != phpTokString && t.kind != phpTokNumber && t.value != " " && t.value != "." {
			return false
		}
	}
	return true
}

func tokenizePHP(src string) []phpToken {
	// Drop everything outside `<?php ... ?>`.
	i := 0
	var out []phpToken
	for i < len(src) {
		o := strings.Index(src[i:], "<?")
		if o < 0 {
			break
		}
		i += o
		// Skip `<?php` / `<?=` / `<?`.
		j := i + 2
		if j < len(src) && (src[j] == '=' || src[j] == 'p' || src[j] == 'P') {
			for j < len(src) && (isAlpha(rune(src[j])) || src[j] == '=') {
				j++
			}
		}
		out = append(out, phpToken{kind: phpTokOpen, value: "<?"})
		// Lex until `?>` or EOF.
		for j < len(src) {
			if j+1 < len(src) && src[j] == '?' && src[j+1] == '>' {
				j += 2
				break
			}
			c := src[j]
			switch {
			case c == ' ' || c == '\t' || c == '\r' || c == '\n':
				j++
			case c == '/' && j+1 < len(src) && src[j+1] == '/':
				for j < len(src) && src[j] != '\n' {
					j++
				}
			case c == '#':
				for j < len(src) && src[j] != '\n' {
					j++
				}
			case c == '/' && j+1 < len(src) && src[j+1] == '*':
				end := strings.Index(src[j+2:], "*/")
				if end < 0 {
					j = len(src)
				} else {
					j += 2 + end + 2
				}
			case c == '$':
				start := j
				j++
				for j < len(src) && (isAlpha(rune(src[j])) || isDigit(rune(src[j])) || src[j] == '_') {
					j++
				}
				out = append(out, phpToken{kind: phpTokVar, value: src[start:j]})
			case c == '\'' || c == '"':
				start := j
				quote := c
				j++
				for j < len(src) {
					if src[j] == '\\' && j+1 < len(src) {
						j += 2
						continue
					}
					if src[j] == quote {
						j++
						break
					}
					j++
				}
				if j > start+1 {
					inner := src[start+1 : j-1]
					out = append(out, phpToken{kind: phpTokString, value: inner})
				}
			case isAlpha(rune(c)) || c == '_':
				start := j
				for j < len(src) && (isAlpha(rune(src[j])) || isDigit(rune(src[j])) || src[j] == '_') {
					j++
				}
				out = append(out, phpToken{kind: phpTokIdent, value: src[start:j]})
			case isDigit(rune(c)):
				start := j
				for j < len(src) && (isDigit(rune(src[j])) || src[j] == '.') {
					j++
				}
				out = append(out, phpToken{kind: phpTokNumber, value: src[start:j]})
			default:
				out = append(out, phpToken{kind: phpTokPunct, value: string(c)})
				j++
			}
		}
		i = j
	}
	return out
}

func isAlpha(r rune) bool {
	return unicode.IsLetter(r)
}

func isDigit(r rune) bool {
	return r >= '0' && r <= '9'
}

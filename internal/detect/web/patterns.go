package web

import "regexp"

// namedPattern is a labelled regex used by the webshell/content detectors.
// Names are stable contract strings surfaced in event.Signals; do not rename.
type namedPattern struct {
	name string
	re   *regexp.Regexp
}

// webPatterns expands the original 5-regex heuristic to 30+ patterns
// covering PHP, JSP, ASP(X) and common obfuscation indicators.
//
// Patterns run against a normalized copy of the file (see normalizeSource)
// so trivial anti-regex tricks such as "ev"."al"( or base64/hex-rot string
// assembly do not evade detection.
var webPatterns = []namedPattern{
	// PHP direct execution surfaces.
	{"dynamic_eval", regexp.MustCompile(`(?i)\b(eval|assert|create_function)\s*\(`)},
	{"php_exec_funcs", regexp.MustCompile(`(?i)\b(shell_exec|passthru|system|exec|popen|proc_open|pcntl_exec|dl|proc_nice)\s*\(`)},
	{"user_input_call", regexp.MustCompile(`(?i)\$_?(GET|POST|REQUEST|COOKIE|SERVER|ENV|FILES)\s*\[\s*['"][^'"]+['"]\s*\]\s*\(`)},
	{"preg_replace_e", regexp.MustCompile(`(?i)preg_replace\s*\([^)]*\/[imsxADSUXJu]*e[imsxADSUXJu]*['"]`)},
	{"reflection_invoke", regexp.MustCompile(`(?i)\bReflectionFunction\b|\bReflectionMethod\b.*invoke`)},
	{"encoding_obfuscation", regexp.MustCompile(`(?i)\b(base64_decode|gzinflate|gzuncompress|str_rot13|convert_uudecode|hex2bin|pack)\s*\(`)},
	{"double_dollar_var_var", regexp.MustCompile(`\$\$[A-Za-z_]`)},
	{"variable_function_call", regexp.MustCompile(`\$[A-Za-z_][A-Za-z0-9_]*\s*\(`)},
	{"backtick_exec", regexp.MustCompile("`[^`\\n]{2,}`")},
	{"globals_bypass", regexp.MustCompile(`(?i)\$\{["']GLOBALS["']\}|\$GLOBALS\[`)},
	{"assert_user_input", regexp.MustCompile(`(?i)assert\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)`)},
	{"include_remote", regexp.MustCompile(`(?i)(include|require)(_once)?\s*\(\s*['"]https?://`)},
	{"chmod_suid", regexp.MustCompile(`(?i)chmod\s*\(\s*[^,]+,\s*0?[2-7]?7[0-7][0-7]\s*\)`)},
	{"file_put_contents_remote", regexp.MustCompile(`(?i)file_put_contents\s*\([^)]*,\s*file_get_contents\s*\(\s*['"]https?://`)},
	{"move_uploaded_file_dynamic", regexp.MustCompile(`(?i)move_uploaded_file\s*\([^)]*\$_FILES`)},
	{"short_eval_payload", regexp.MustCompile(`(?s)<\?(php|=)?\s*@?(eval|assert)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[`)},

	// JSP / Java.
	{"jsp_runtime_exec", regexp.MustCompile(`(?i)Runtime\.getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(`)},
	{"jsp_processbuilder", regexp.MustCompile(`(?i)new\s+ProcessBuilder\s*\(`)},
	{"jsp_scriptlet_exec", regexp.MustCompile(`(?s)<%\s*@?\s*.{0,200}Runtime\s*\.`)},
	{"jsp_class_loader", regexp.MustCompile(`(?i)defineClass\s*\(|ClassLoader\s*\(\s*\)\s*\.\s*defineClass`)},

	// ASP / ASPX.
	{"aspx_process_start", regexp.MustCompile(`(?i)System\.Diagnostics\.Process\s*\.\s*Start\s*\(`)},
	{"aspx_response_write_eval", regexp.MustCompile(`(?i)Response\.Write\s*\(.*\bRequest\s*\[`)},
	{"aspx_unsafe_new_sprocess", regexp.MustCompile(`(?i)new\s+Process\s*\(\s*\)|ProcessStartInfo`)},

	// Generic high-entropy / encoded payload hints.
	{"long_base64_blob", regexp.MustCompile(`(?:[A-Za-z0-9+/]{120,}={0,2})`)},
	{"hex_blob", regexp.MustCompile(`(?:\\x[0-9a-fA-F]{2}){20,}`)},
	{"chr_chain", regexp.MustCompile(`(?i)(chr\s*\(\s*\d{1,3}\s*\)\s*\.\s*){4,}`)},
	{"eval_gzinflate_chain", regexp.MustCompile(`(?is)eval\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13)`)},
	{"reverse_shell_socket", regexp.MustCompile(`(?i)fsockopen\s*\(|socket_connect\s*\(|stream_socket_client\s*\(`)},
	{"php_wrapper_abuse", regexp.MustCompile(`(?i)php://(input|filter|memory|temp)`)},
	{"data_wrapper_exec", regexp.MustCompile(`(?i)data://text/plain[;,]`)},

	// Shell / universal.
	{"bash_reverse_shell", regexp.MustCompile(`/dev/tcp/\d`)},
	{"call_user_func_eval", regexp.MustCompile(`(?i)call_user_func(_array)?\s*\(\s*['"](eval|assert|system|exec|passthru|shell_exec|pcntl_exec)['"]`)},
}

// suspiciousExtensions lists file suffixes worth content-scanning for shell-like
// patterns. The extension is case-insensitive. Content detection also runs on
// files without these suffixes when magicByteMismatch returns true (polyglot).
var suspiciousExtensions = []string{
	".php", ".php3", ".php4", ".php5", ".php7", ".phtml", ".phar", ".inc",
	".jsp", ".jspx", ".jhtml",
	".asp", ".aspx", ".ashx", ".asmx",
	".cfm", ".cfml",
	".pl", ".cgi",
}

// matchingPatterns returns the names of all patterns matching a suspect file.
//
// Most patterns run against a normalized copy (comments stripped, concat
// collapsed, short base64 blobs decoded) so obfuscation cannot hide the
// sink. Encoded-blob patterns listed in rawOnlyPatterns run against the
// original bytes so normalization does not erase their own signal.
func matchingPatterns(content string) []string {
	normalized := normalizeSource(content)
	var out []string
	for _, p := range webPatterns {
		target := normalized
		if _, raw := rawOnlyPatterns[p.name]; raw {
			target = content
		}
		if p.re.FindStringIndex(target) != nil {
			out = append(out, p.name)
		}
	}
	return out
}

// rawOnlyPatterns names patterns whose meaning is the raw byte shape of
// the file, so normalization (which strips/collapses text) would erase
// them instead of helping.
var rawOnlyPatterns = map[string]struct{}{
	"long_base64_blob": {},
	"hex_blob":         {},
	"chr_chain":        {},
}

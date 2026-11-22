package har

import (
	"strings"
	"unicode"
)

// The secret-name rules below are shared by Redact and by analysis
// (internal/analyze), so a value one of them treats as a secret the other
// does too.
var (
	secretHeaderWords = []string{"token", "csrf", "xsrf", "session", "auth", "secret", "password", "api-key", "apikey", "api_key", "cookie"}
	secretFieldExact  = map[string]bool{
		"password": true, "passwd": true, "pwd": true, "pass": true, "pw": true, "token": true, "csrf": true,
		"sid": true, "stok": true, "secret": true, "pin": true, "psk": true, "otp": true,
	}
	secretFieldWords = []string{
		"password", "passwd", "passphrase", "token", "csrf", "xsrf", "secret", "sessid", "sessionid", "session_id",
		"apikey", "api_key", "access_key", "private_key", "psk", "wpa_key", "wpakey", "wifi_key", "wifikey",
	}
	// secretLabelWords are whole words in a form field's label or name that
	// mark what is typed into it as a secret, such as "Wi-Fi password" or
	// "WPA key".
	secretLabelWords = map[string]bool{
		"password": true, "passwd": true, "passphrase": true, "passcode": true, "pwd": true, "psk": true,
		"pin": true, "secret": true, "key": true, "token": true, "wpa": true, "wpa2": true, "wpa3": true,
	}
	// commonPasswords are default and common passwords that are also
	// ordinary words in URLs and values, so they are never removed from the
	// middle of other text.
	commonPasswords = map[string]bool{
		"admin": true, "administrator": true, "password": true, "passw0rd": true, "password1": true, "password123": true,
		"p@ssw0rd": true, "root": true, "toor": true, "user": true, "guest": true, "default": true, "changeme": true,
		"letmein": true, "welcome": true, "qwerty": true, "qwerty123": true, "abc123": true, "admin1": true,
		"admin123": true, "admin1234": true, "support": true, "service": true, "private": true, "public": true,
		"secret": true, "manager": true, "operator": true, "ubnt": true, "raspberry": true, "test": true,
		"test123": true, "demo": true, "system": true, "1234qwer": true, "123456": true, "12345678": true,
		"123456789": true, "1234567890": true,
	}
)

// lastDotted is the last part of a dotted path ("data.token" -> "token").
func lastDotted(name string) string {
	if i := strings.LastIndexByte(name, '.'); i >= 0 {
		return name[i+1:]
	}
	return name
}

// IsSecretHeader reports whether a header name suggests its value is a
// credential: Cookie, Set-Cookie, Authorization, or a name containing
// token, csrf, session, auth, secret, password or an API-key word.
func IsSecretHeader(name string) bool {
	n := strings.ToLower(name)
	for _, w := range secretHeaderWords {
		if strings.Contains(n, w) {
			return true
		}
	}
	return false
}

// IsSecretField reports whether a JSON, form or query field name suggests a
// credential: password, token, csrf, sid, stok, pin, psk and the like. For
// a dotted path only the last part counts.
func IsSecretField(name string) bool {
	n := strings.ToLower(lastDotted(name))
	if secretFieldExact[n] {
		return true
	}
	for _, w := range secretFieldWords {
		if strings.Contains(n, w) {
			return true
		}
	}
	return false
}

// IsPasswordField reports whether a field name is a password field. For a
// dotted path only the last part counts.
func IsPasswordField(name string) bool {
	n := strings.ToLower(lastDotted(name))
	switch n {
	case "password", "passwd", "pwd", "pass", "passphrase", "pass_word", "pw":
		return true
	}
	return strings.Contains(n, "password") || strings.Contains(n, "passwd")
}

// IsSecretInput reports whether a typed form field holds a secret: a
// password field, or one whose label or name says password, passphrase,
// key, PSK, PIN or secret. Routers often show a Wi-Fi key in a plain text
// field.
func IsSecretInput(in TypedInput) bool {
	if strings.EqualFold(in.Type, "password") || IsSecretField(in.Name) {
		return true
	}
	for _, s := range []string{in.Label, in.Name} {
		for _, w := range labelWords(s) {
			if secretLabelWords[w] {
				return true
			}
		}
	}
	return false
}

// labelWords splits a label or field name into lower-case words at spaces,
// punctuation and camelCase boundaries: "wifiKey" -> wifi, key.
func labelWords(s string) []string {
	var words []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			words = append(words, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}
	var prev rune
	for _, r := range s {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			if unicode.IsUpper(r) && unicode.IsLower(prev) {
				flush()
			}
			cur = append(cur, r)
		default:
			flush()
		}
		prev = r
	}
	flush()
	return words
}

// Distinctive reports whether a password is distinctive enough to remove
// wherever it appears, even inside other text: at least 12 characters, or
// at least 6 mixing letters, digits or symbols, and not a common password.
// Short or common passwords such as "admin" or "1234" are also ordinary
// words in paths and values, so they are only removed where a whole value
// equals them.
func Distinctive(v string) bool {
	if commonPasswords[strings.ToLower(v)] {
		return false
	}
	if len(v) >= 12 {
		return true
	}
	return len(v) >= 6 && charClasses(v) >= 2
}

// charClasses counts the kinds of characters in v: lower case, upper case,
// digits and everything else.
func charClasses(v string) int {
	var lower, upper, digit, other bool
	for _, r := range v {
		switch {
		case unicode.IsLower(r):
			lower = true
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsDigit(r):
			digit = true
		default:
			other = true
		}
	}
	n := 0
	for _, b := range []bool{lower, upper, digit, other} {
		if b {
			n++
		}
	}
	return n
}

// LooksSecret reports whether a value found in a secret place (a cookie, a
// token header, a secret-named field) is distinctive enough to remove
// everywhere else without mangling ordinary text: at least 6 characters
// with a digit, or at least 12 characters.
func LooksSecret(v string) bool {
	if v == Redacted || len(v) < 6 {
		return false
	}
	if len(v) >= 12 {
		return true
	}
	return strings.IndexFunc(v, unicode.IsDigit) >= 0
}

// tokenish reports whether a value a response returned could be a session
// token: letters and digits mixed, at least 8 characters, or at least 20
// characters with a letter.
func tokenish(v string) bool {
	if len(v) < 8 || strings.IndexFunc(v, unicode.IsSpace) >= 0 {
		return false
	}
	letter := strings.IndexFunc(v, unicode.IsLetter) >= 0
	digit := strings.IndexFunc(v, unicode.IsDigit) >= 0
	return letter && (digit || len(v) >= 20)
}

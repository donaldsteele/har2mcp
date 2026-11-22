package spec

import (
	"strconv"
	"strings"
)

// maxNameLen is the longest MCP tool name the spec allows.
const maxNameLen = 64

// SanitizeName turns a free-text label into a snake_case name matching
// ^[a-z][a-z0-9_]*$, at most maxLen characters long (64 when maxLen <= 0).
//
// Accented Latin letters are folded to ASCII ("Ünïcode" -> "unicode"), other
// non-ASCII characters and punctuation separate words, and camelCase is split
// ("getDiskList" -> "get_disk_list"). A name starting with a digit gets an
// "x_" prefix; a label with no usable characters becomes "unnamed".
// Truncation never leaves a trailing "_".
func SanitizeName(label string, maxLen int) string {
	if maxLen <= 0 {
		maxLen = maxNameLen
	}
	// Fold to ASCII letters and digits; everything else becomes a space.
	var folded []rune
	for _, r := range label {
		switch {
		case r < 0x80 && (isLower(r) || isUpper(r) || isDigit(r)):
			folded = append(folded, r)
		case foldTable[r] != "":
			folded = append(folded, []rune(foldTable[r])...)
		default:
			folded = append(folded, ' ')
		}
	}
	// Split camelCase: aB -> a_B, and ABc -> A_Bc (end of an acronym).
	var b strings.Builder
	for i, r := range folded {
		if i > 0 && isUpper(r) {
			prev := folded[i-1]
			nextLower := i+1 < len(folded) && isLower(folded[i+1])
			if isLower(prev) || (isUpper(prev) && nextLower) {
				b.WriteByte('_')
			}
		}
		if isUpper(r) {
			r += 'a' - 'A'
		}
		if r == ' ' {
			r = '_'
		}
		b.WriteRune(r)
	}
	// Collapse runs of "_" and trim them from the ends.
	parts := strings.FieldsFunc(b.String(), func(r rune) bool { return r == '_' })
	name := strings.Join(parts, "_")
	if name == "" {
		name = "unnamed"
	}
	if isDigit(rune(name[0])) {
		name = "x_" + name
	}
	if len(name) > maxLen {
		name = strings.TrimRight(name[:maxLen], "_")
	}
	return name
}

// UniqueName returns base if it is not in taken, else the first of base_2,
// base_3, ... that is not, shortening base so the result stays within 64
// characters. The returned name is recorded in taken (when taken is not nil).
func UniqueName(base string, taken map[string]bool) string {
	name := base
	for n := 2; taken[name]; n++ {
		suffix := "_" + strconv.Itoa(n)
		b := base
		if len(b)+len(suffix) > maxNameLen {
			b = strings.TrimRight(b[:maxNameLen-len(suffix)], "_")
		}
		name = b + suffix
	}
	if taken != nil {
		taken[name] = true
	}
	return name
}

// GoKeywords holds the Go keywords and predeclared identifiers. Generated
// code must not use them as tool-derived identifiers.
var GoKeywords = map[string]bool{
	// Keywords.
	"break": true, "case": true, "chan": true, "const": true, "continue": true,
	"default": true, "defer": true, "else": true, "fallthrough": true, "for": true,
	"func": true, "go": true, "goto": true, "if": true, "import": true,
	"interface": true, "map": true, "package": true, "range": true, "return": true,
	"select": true, "struct": true, "switch": true, "type": true, "var": true,
	// Predeclared types.
	"any": true, "bool": true, "byte": true, "comparable": true, "complex64": true,
	"complex128": true, "error": true, "float32": true, "float64": true, "int": true,
	"int8": true, "int16": true, "int32": true, "int64": true, "rune": true,
	"string": true, "uint": true, "uint8": true, "uint16": true, "uint32": true,
	"uint64": true, "uintptr": true,
	// Predeclared constants and the zero value.
	"true": true, "false": true, "iota": true, "nil": true,
	// Predeclared functions.
	"append": true, "cap": true, "clear": true, "close": true, "complex": true,
	"copy": true, "delete": true, "imag": true, "len": true, "make": true,
	"max": true, "min": true, "new": true, "panic": true, "print": true,
	"println": true, "real": true, "recover": true,
}

func isLower(r rune) bool { return r >= 'a' && r <= 'z' }
func isUpper(r rune) bool { return r >= 'A' && r <= 'Z' }
func isDigit(r rune) bool { return r >= '0' && r <= '9' }

// foldTable maps accented Latin letters (Latin-1 Supplement and Latin
// Extended-A) to ASCII, keeping case.
var foldTable = func() map[rune]string {
	groups := map[string]string{
		"a": "àáâãäåāăą", "A": "ÀÁÂÃÄÅĀĂĄ",
		"c": "çćĉċč", "C": "ÇĆĈĊČ",
		"d": "ðďđ", "D": "ÐĎĐ",
		"e": "èéêëēĕėęě", "E": "ÈÉÊËĒĔĖĘĚ",
		"g": "ĝğġģ", "G": "ĜĞĠĢ",
		"h": "ĥħ", "H": "ĤĦ",
		"i": "ìíîïĩīĭįı", "I": "ÌÍÎÏĨĪĬĮİ",
		"j": "ĵ", "J": "Ĵ",
		"k": "ķ", "K": "Ķ",
		"l": "ĺļľŀł", "L": "ĹĻĽĿŁ",
		"n": "ñńņňŉ", "N": "ÑŃŅŇ",
		"o": "òóôõöøōŏő", "O": "ÒÓÔÕÖØŌŎŐ",
		"r": "ŕŗř", "R": "ŔŖŘ",
		"s": "śŝşš", "S": "ŚŜŞŠ",
		"t": "ţťŧ", "T": "ŢŤŦ",
		"u": "ùúûüũūŭůűų", "U": "ÙÚÛÜŨŪŬŮŰŲ",
		"w": "ŵ", "W": "Ŵ",
		"y": "ýÿŷ", "Y": "ÝŶŸ",
		"z": "źżž", "Z": "ŹŻŽ",
		"ae": "æ", "Ae": "Æ", "oe": "œ", "Oe": "Œ", "ss": "ß", "th": "þ", "Th": "Þ",
	}
	m := map[rune]string{}
	for ascii, letters := range groups {
		for _, r := range letters {
			m[r] = ascii
		}
	}
	return m
}()

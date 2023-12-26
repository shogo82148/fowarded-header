package fowardedheader

import (
	"io"
	"strings"
)

// Forwarded represents the Forwarded header.
type Forwarded struct {
	// By is used to disclose the interface where the request came in to the proxy server.
	By string

	// For is used to disclose information about the client that initiated the request and subsequent proxies in a chain of proxies.
	For string

	// Host is used to forward the original value of the "Host" header field.
	Host string

	// Proto is the value of the used protocol type.
	Proto string
}

var validTchar = [256]bool{
	'!':  true,
	'#':  true,
	'$':  true,
	'%':  true,
	'&':  true,
	'\'': true,
	'*':  true,
	'+':  true,
	'-':  true,
	'.':  true,
	'^':  true,
	'_':  true,
	'`':  true,
	'|':  true,
	'~':  true,

	// DIGIT
	'0': true,
	'1': true,
	'2': true,
	'3': true,
	'4': true,
	'5': true,
	'6': true,
	'7': true,
	'8': true,
	'9': true,

	// ALPHA
	'a': true,
	'b': true,
	'c': true,
	'd': true,
	'e': true,
	'f': true,
	'g': true,
	'h': true,
	'i': true,
	'j': true,
	'k': true,
	'l': true,
	'm': true,
	'n': true,
	'o': true,
	'p': true,
	'q': true,
	'r': true,
	's': true,
	't': true,
	'u': true,
	'v': true,
	'w': true,
	'x': true,
	'y': true,
	'z': true,
	'A': true,
	'B': true,
	'C': true,
	'D': true,
	'E': true,
	'F': true,
	'G': true,
	'H': true,
	'I': true,
	'J': true,
	'K': true,
	'L': true,
	'M': true,
	'N': true,
	'O': true,
	'P': true,
	'Q': true,
	'R': true,
	'S': true,
	'T': true,
	'U': true,
	'V': true,
	'W': true,
	'X': true,
	'Y': true,
	'Z': true,
}

func IsValidToken(s string) bool {
	for _, r := range []byte(s) {
		if !validTchar[r] {
			return false
		}
	}
	return true
}

func writeQuotedString(w io.ByteWriter, s string) {
	w.WriteByte('"')
	for _, r := range []byte(s) {
		if r == '"' || r == '\\' {
			w.WriteByte('\\')
		}
		w.WriteByte(r)
	}
	w.WriteByte('"')
}

func writePair(buf *strings.Builder, key, value string) {
	if value == "" {
		return
	}
	if buf.Len() > 0 {
		buf.WriteByte(';')
	}

	buf.WriteString(key)
	buf.WriteByte('=')
	if IsValidToken(value) {
		buf.WriteString(value)
	} else {
		writeQuotedString(buf, value)
	}
}

// String returns the string representation of the Forwarded header.
// The returned string is a valid Forwarded header.
func (f *Forwarded) String() string {
	var buf strings.Builder
	writePair(&buf, "by", f.By)
	writePair(&buf, "for", f.For)
	writePair(&buf, "host", f.Host)
	writePair(&buf, "proto", f.Proto)
	return buf.String()
}

func Parse(h []string) ([]*Forwarded, error) {
	return []*Forwarded{}, nil
}

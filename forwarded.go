package fowardedheader

import (
	"fmt"
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

// Error represents an error that occurred while parsing the Forwarded header.
type Error struct {
	Message string
	Index   int
	Pos     int
}

func (e *Error) Error() string {
	return fmt.Sprintf("forwardedheader: %s at %d in %d", e.Message, e.Pos, e.Index)
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

// Parse parses the Forwarded header.
func Parse(h []string) ([]*Forwarded, error) {
	ret := []*Forwarded{}
	for i, s := range h {
		var err error
		p := &parser{s: s, index: i}
		ret, err = p.parse(ret)
		if err != nil {
			return nil, err
		}
	}
	return ret, nil
}

type parser struct {
	s     string
	pos   int
	index int
}

// peek returns the next byte without advancing the parser.
func (p *parser) peek() int {
	if p.pos >= len(p.s) {
		return -1
	}
	return int(p.s[p.pos])
}

// next advances the parser and returns the current position.
func (p *parser) next() int {
	if p.pos >= len(p.s) {
		return -1
	}
	p.pos++
	return p.pos
}

func (p *parser) skipSpace() {
	for ch := p.peek(); ch == ' ' || ch == '\t'; ch = p.peek() {
		p.next()
	}
}

func (p *parser) newError(msg string) error {
	return &Error{
		Message: msg,
		Index:   p.index,
		Pos:     p.pos,
	}
}

// decodeToken decodes a token that is defined in RFC 7239 Section 4.
func (p *parser) decodeToken() (string, error) {
	p.skipSpace()
	start := p.pos
	for ch := p.peek(); ch >= 0 && validTchar[ch]; ch = p.peek() {
		p.next()
	}
	if start == p.pos {
		return "", nil
	}
	return p.s[start:p.pos], nil
}

// decodeQuotedString decodes a quoted-string that is defined in RFC 7239 Section 4.
func (p *parser) decodeQuotedString() (string, error) {
	p.skipSpace()
	if p.peek() != '"' {
		return "", p.newError("expected '\"' but not")
	}
	p.next()

	var buf strings.Builder
	for {
		ch := p.peek()
		if ch < 0 {
			return "", p.newError("unexpected EOF")
		}
		if ch == '"' {
			p.next()
			break
		}
		if ch == '\\' {
			p.next()
			ch = p.peek()
			if ch < 0 {
				return "", p.newError("unexpected EOF")
			}
		}
		buf.WriteByte(byte(ch))
		p.next()
	}

	return buf.String(), nil
}

// decodeValue decodes a value that is defined in RFC 7239 Section 4.
func (p *parser) decodeValue() (string, error) {
	p.skipSpace()
	if p.peek() == '"' {
		return p.decodeQuotedString()
	}
	return p.decodeToken()
}

// decodeForwardedPair decodes a forwarded-pair that is defined in RFC 7239 Section 4.
func (p *parser) decodeForwardedPair() (string, string, error) {
	key, err := p.decodeToken()
	if err != nil {
		return "", "", err
	}

	p.skipSpace()
	if p.peek() != '=' {
		return "", "", p.newError("expected '=' but not")
	}
	p.next()

	value, err := p.decodeValue()
	if err != nil {
		return "", "", err
	}
	return key, value, nil
}

// decodeForwardedElement decodes a forwarded-element that is defined in RFC 7239 Section 4.
func (p *parser) decodeForwardedElement() (*Forwarded, error) {
	seen := map[string]bool{}
	f := &Forwarded{}
	for {
		if len(seen) > 0 {
			p.skipSpace()
			if p.peek() != ';' {
				return f, nil
			}
		}
		key, value, err := p.decodeForwardedPair()
		if err != nil {
			return nil, err
		}
		key = strings.ToLower(key)
		if seen[key] {
			return nil, p.newError("duplicate key")
		}
		seen[key] = true

		switch key {
		case "by":
			f.By = value
		case "for":
			f.For = value
		case "host":
			f.Host = value
		case "proto":
			f.Proto = value
		}
	}
}

func (p *parser) parse(f []*Forwarded) ([]*Forwarded, error) {
	elem, err := p.decodeForwardedElement()
	if err != nil {
		return nil, err
	}
	f = append(f, elem)

	for {
		p.skipSpace()
		ch := p.peek()
		if ch < 0 {
			// EOF
			break
		}
		if ch != ',' {
			return f, p.newError("expected ',' but not")
		}
		p.next()
		elem, err := p.decodeForwardedElement()
		if err != nil {
			return nil, err
		}
		f = append(f, elem)
	}
	return f, nil
}

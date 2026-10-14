/*
©AngelaMos | 2026
negotiate.go

Telnet IAC (Interpret As Command) option negotiation

Sends the minimal negotiation sequence needed for interactive
terminal clients (real telnet, PuTTY, netcat-with-telnet-mode) to
render a usable prompt: server-side echo, suppressed go-ahead, and
no linemode. Also provides a reader that transparently strips any
IAC sequences the client sends back (option replies, NAWS window
size subnegotiation, etc.) so the shell loop only ever sees typed
bytes.
*/

package telnetd

import (
	"io"
	"net"
)

const (
	iac  = 255
	will = 251
	wont = 252
	do   = 253
	dont = 254
	sb   = 250
	se   = 240

	optEcho       = 1
	optSuppressGA = 3
	optLinemode   = 34
)

func negotiate(conn net.Conn) {
	seq := []byte{
		iac, will, optEcho,
		iac, will, optSuppressGA,
		iac, wont, optLinemode,
		iac, do, optSuppressGA,
	}
	_, _ = conn.Write(seq)
}

// iacStrippingReader wraps a net.Conn and consumes any Telnet IAC
// sequences embedded in the client's data stream, exposing only the
// "real" typed bytes to callers. Option negotiation replies and
// subnegotiation blocks (IAC SB ... IAC SE) are discarded rather
// than acted on; the honeypot doesn't need real NAWS/terminal-type
// negotiation to sustain a convincing shell session.
type iacStrippingReader struct {
	r io.Reader
}

func newIACStrippingReader(r io.Reader) *iacStrippingReader {
	return &iacStrippingReader{r: r}
}

func (r *iacStrippingReader) Read(p []byte) (int, error) {
	raw := make([]byte, len(p))
	n, err := r.r.Read(raw)
	if n == 0 {
		return 0, err
	}

	out := p[:0]
	i := 0
	for i < n {
		b := raw[i]

		if b != iac {
			out = append(out, b)
			i++
			continue
		}

		if i+1 >= n {
			// Trailing IAC with no command byte yet; drop it.
			i++
			continue
		}

		switch raw[i+1] {
		case iac:
			// Escaped 0xFF literal byte.
			out = append(out, iac)
			i += 2

		case will, wont, do, dont:
			if i+2 >= n {
				i = n
				continue
			}
			i += 3

		case sb:
			j := i + 2
			for j+1 < n && !(raw[j] == iac && raw[j+1] == se) {
				j++
			}
			i = j + 2

		default:
			i += 2
		}
	}

	return len(out), err
}

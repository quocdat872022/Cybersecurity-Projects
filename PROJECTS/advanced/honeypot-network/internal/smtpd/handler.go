/*
©AngelaMos | 2026
handler.go

SMTP protocol state machine for the honeypot

Implements enough of RFC 5321 to sustain a full mail transaction:
EHLO/HELO, MAIL FROM, RCPT TO, DATA (with dot-stuffing removal),
RSET, NOOP, VRFY, and AUTH LOGIN/PLAIN credential capture. STARTTLS
is acknowledged but refused so the session stays plaintext and
observable.
*/

package smtpd

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"regexp"
	"strings"
)

const (
	maxBodyCapture = 1 << 20 // 1MB
	maxRcpts       = 50
)

var addrPattern = regexp.MustCompile(`<([^<>]*)>`)

type smtpConn struct {
	ctrl     net.Conn
	reader   *bufio.Reader
	hostname string
	banner   string

	heloHost string
	from     string
	to       []string
	inData   bool
	body     strings.Builder
	bodyLen  int

	authUser string
	authStep string // "", "login-user", "login-pass", "plain"
}

func newSMTPConn(conn net.Conn, banner, hostname string) *smtpConn {
	return &smtpConn{
		ctrl:     conn,
		reader:   bufio.NewReader(conn),
		hostname: hostname,
		banner:   banner,
	}
}

func (c *smtpConn) reply(code int, msg string) {
	fmt.Fprintf(c.ctrl, "%d %s\r\n", code, msg)
}

func (c *smtpConn) replyMulti(code int, lines ...string) {
	for i, line := range lines {
		sep := "-"
		if i == len(lines)-1 {
			sep = " "
		}
		fmt.Fprintf(c.ctrl, "%d%s%s\r\n", code, sep, line)
	}
}

func (c *smtpConn) greet() {
	c.reply(220, c.banner)
}

func (c *smtpConn) readLine() (string, error) {
	line, err := c.reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

type mailResult struct {
	from string
	to   []string
	body string
}

type credResult struct {
	username string
	password string
	method   string
}

type dispatchResult struct {
	cmd   string
	arg   string
	quit  bool
	mail  *mailResult
	creds *credResult
}

func (c *smtpConn) dispatch(line string) dispatchResult {
	if c.inData {
		return c.handleDataLine(line)
	}

	if c.authStep != "" {
		return c.handleAuthLine(line)
	}

	parts := strings.SplitN(line, " ", 2)
	cmd := strings.ToUpper(parts[0])
	arg := ""
	if len(parts) > 1 {
		arg = strings.TrimSpace(parts[1])
	}

	res := dispatchResult{cmd: cmd, arg: arg}

	switch cmd {
	case "HELO":
		c.heloHost = arg
		c.reply(250, c.hostname+" Hello "+arg)

	case "EHLO":
		c.heloHost = arg
		c.replyMulti(250,
			c.hostname+" Hello "+arg,
			"SIZE 10485760",
			"8BITMIME",
			"AUTH LOGIN PLAIN",
			"STARTTLS",
		)

	case "MAIL":
		addr := extractAddr(arg)
		if addr == "" {
			c.reply(501, "Syntax error in parameters")
			break
		}
		c.from = addr
		c.to = nil
		c.reply(250, "OK")

	case "RCPT":
		if c.from == "" {
			c.reply(503, "Need MAIL before RCPT")
			break
		}
		addr := extractAddr(arg)
		if addr == "" {
			c.reply(501, "Syntax error in parameters")
			break
		}
		if len(c.to) < maxRcpts {
			c.to = append(c.to, addr)
		}
		c.reply(250, "OK")

	case "DATA":
		if c.from == "" || len(c.to) == 0 {
			c.reply(503, "Need MAIL and RCPT before DATA")
			break
		}
		c.inData = true
		c.body.Reset()
		c.bodyLen = 0
		c.reply(354, "Start mail input; end with <CRLF>.<CRLF>")

	case "RSET":
		c.from = ""
		c.to = nil
		c.body.Reset()
		c.bodyLen = 0
		c.reply(250, "OK")

	case "NOOP":
		c.reply(250, "OK")

	case "VRFY":
		c.reply(252, "Cannot VRFY user, but will accept message")

	case "STARTTLS":
		// Refuse and keep the session in plaintext so it stays observable.
		c.reply(454, "TLS not available due to temporary reason")

	case "AUTH":
		res = c.startAuth(arg, res)

	case "QUIT":
		c.reply(221, c.hostname+" closing connection")
		res.quit = true

	case "":
		c.reply(500, "Command unrecognized")

	default:
		c.reply(502, "Command not implemented")
	}

	return res
}

func (c *smtpConn) startAuth(arg string, res dispatchResult) dispatchResult {
	fields := strings.Fields(arg)
	if len(fields) == 0 {
		c.reply(501, "Syntax error in parameters")
		return res
	}

	switch strings.ToUpper(fields[0]) {
	case "LOGIN":
		if len(fields) > 1 {
			c.authUser = decodeB64(fields[1])
			c.authStep = "login-pass"
			c.reply(334, "UGFzc3dvcmQ6") // "Password:"
			return res
		}
		c.authStep = "login-user"
		c.reply(334, "VXNlcm5hbWU6") // "Username:"

	case "PLAIN":
		if len(fields) > 1 {
			return c.finishPlainAuth(fields[1], res)
		}
		c.authStep = "plain"
		c.reply(334, "")

	default:
		c.reply(504, "Unrecognized authentication type")
	}

	return res
}

func (c *smtpConn) handleAuthLine(line string) dispatchResult {
	res := dispatchResult{cmd: "AUTH-CONT"}

	if line == "*" {
		c.authStep = ""
		c.reply(501, "Authentication cancelled")
		return res
	}

	switch c.authStep {
	case "login-user":
		c.authUser = decodeB64(line)
		c.authStep = "login-pass"
		c.reply(334, "UGFzc3dvcmQ6")
		return res

	case "login-pass":
		password := decodeB64(line)
		c.authStep = ""
		res.creds = &credResult{
			username: c.authUser, password: password, method: "LOGIN",
		}
		c.reply(535, "Authentication credentials invalid")
		return res

	case "plain":
		return c.finishPlainAuth(line, res)
	}

	c.authStep = ""
	c.reply(501, "Authentication failed")
	return res
}

func (c *smtpConn) finishPlainAuth(
	encoded string, res dispatchResult,
) dispatchResult {
	c.authStep = ""
	decoded := decodeB64(encoded)

	// AUTH PLAIN payload: authzid \0 authcid \0 password
	parts := strings.Split(decoded, "\x00")
	var username, password string
	switch len(parts) {
	case 3:
		username, password = parts[1], parts[2]
	case 2:
		username, password = parts[0], parts[1]
	}

	res.creds = &credResult{
		username: username, password: password, method: "PLAIN",
	}
	c.reply(535, "Authentication credentials invalid")
	return res
}

func (c *smtpConn) handleDataLine(line string) dispatchResult {
	if line == "." {
		c.inData = false
		body := c.body.String()
		c.reply(250, "OK: message queued")

		result := dispatchResult{
			cmd: "DATA",
			mail: &mailResult{
				from: c.from,
				to:   append([]string(nil), c.to...),
				body: body,
			},
		}

		c.from = ""
		c.to = nil
		c.body.Reset()
		c.bodyLen = 0

		return result
	}

	// Undo dot-stuffing (RFC 5321 §4.5.2): a line starting with ".."
	// represents a literal line starting with "."
	if strings.HasPrefix(line, "..") {
		line = line[1:]
	}

	if c.bodyLen < maxBodyCapture {
		remaining := maxBodyCapture - c.bodyLen
		toWrite := line + "\n"
		if len(toWrite) > remaining {
			toWrite = toWrite[:remaining]
		}
		c.body.WriteString(toWrite)
		c.bodyLen += len(toWrite)
	}

	return dispatchResult{cmd: "DATA-LINE"}
}

func extractAddr(arg string) string {
	if m := addrPattern.FindStringSubmatch(arg); len(m) == 2 {
		return strings.TrimSpace(m[1])
	}
	if fields := strings.Fields(arg); len(fields) > 0 {
		return strings.Trim(fields[0], "<>")
	}
	return ""
}

func decodeB64(s string) string {
	data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return ""
	}
	return string(data)
}

/*
©AngelaMos | 2026
shell.go

Login prompt and fake shell loop for the Telnet honeypot

Presents a Linux-style "login:" / "Password:" prompt that accepts
any credentials, then drops the attacker into the same fake command
environment used by the SSH honeypot: FakeFS for filesystem reads
and DispatchCommand for command execution. All I/O is captured by
the asciicast recorder so sessions are replayable in the dashboard
alongside SSH sessions.
*/

package telnetd

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/CarterPerez-dev/hive/internal/config"
	"github.com/CarterPerez-dev/hive/internal/session"
	"github.com/CarterPerez-dev/hive/internal/sshd"
	"github.com/CarterPerez-dev/hive/pkg/types"
)

func (s *TelnetService) readLine(
	conn net.Conn, r *bufio.Reader, echoInput bool,
) (string, error) {
	var buf []byte
	for {
		b, err := r.ReadByte()
		if err != nil {
			return "", err
		}

		if b == '\r' {
			// Telnet NVT: Enter is CR, optionally followed by LF
			// or NUL. Peek and discard that follow-up byte without
			// blocking if the client hasn't sent it yet.
			if next, peekErr := r.Peek(1); peekErr == nil &&
				(next[0] == '\n' || next[0] == 0x00) {
				_, _ = r.ReadByte()
			}
			break
		}
		if b == '\n' {
			break
		}

		if b == 0x7f || b == 0x08 { // DEL / backspace
			if len(buf) > 0 {
				buf = buf[:len(buf)-1]
				if echoInput {
					_, _ = conn.Write([]byte("\b \b"))
				}
			}
			continue
		}

		buf = append(buf, b)
		if echoInput {
			_, _ = conn.Write([]byte{b})
		}
	}
	_, _ = conn.Write([]byte("\r\n"))
	return string(buf), nil
}

func writeAndRecord(
	w io.Writer, recorder *session.Recorder, data []byte,
) {
	_, _ = w.Write(data)
	recorder.WriteOutput(data)
}

func (s *TelnetService) promptLogin(
	conn net.Conn, reader *bufio.Reader, recorder *session.Recorder,
) (username, password string, ok bool) {
	banner := fmt.Sprintf(
		"%s\r\n\r\n%s login: ",
		s.cfg.Telnet.Banner, s.cfg.Telnet.Hostname,
	)
	writeAndRecord(conn, recorder, []byte(banner))

	user, err := s.readLine(conn, reader, true) // echo username
	if err != nil {
		return "", "", false
	}
	recorder.WriteInput([]byte(user + "\n"))

	writeAndRecord(conn, recorder, []byte("Password: "))
	pass, err := s.readLine(conn, reader, false) // hide password
	if err != nil {
		return "", "", false
	}
	recorder.WriteInput([]byte(strings.Repeat("*", len(pass)) + "\n"))

	if strings.TrimSpace(user) == "" {
		user = "root"
	}

	return strings.TrimSpace(user), pass, true
}

func (s *TelnetService) runShell(
	ctx context.Context,
	conn net.Conn,
	reader *bufio.Reader,
	sess *types.Session,
	srcIP string,
	username string,
	recorder *session.Recorder,
) {

	banner := fmt.Sprintf(
		config.TelnetMOTDTemplate,
	)

	writeAndRecord(conn, recorder, []byte(banner))

	fs := sshd.NewFakeFS(s.cfg.Telnet.Hostname)
	cmdCtx := &sshd.CommandContext{
		FS:       fs,
		Hostname: s.cfg.Telnet.Hostname,
		Username: username,
		CWD:      "/root",
	}

	prompt := func() string {
		return fmt.Sprintf(
			"%s@%s:%s$ ",
			username, s.cfg.Telnet.Hostname, cmdCtx.CWD,
		)
	}

	writeAndRecord(conn, recorder, []byte(prompt()))

	for {
		if ctx.Err() != nil {
			return
		}

		line, err := s.readLine(conn, reader, true) // echo commands
		if err != nil {
			return
		}

		line = strings.TrimSpace(line)
		if line == "" {
			writeAndRecord(conn, recorder, []byte(prompt()))
			continue
		}

		recorder.WriteInput([]byte(line + "\n"))
		s.publishCommand(sess.ID, srcIP, line)
		s.tracker.IncrCommandCount(sess.ID)

		if line == "exit" || line == "logout" || line == "quit" {
			writeAndRecord(conn, recorder, []byte("logout\r\n"))
			return
		}

		output := sshd.DispatchCommand(line, cmdCtx)
		if output != "" {
			crlf := strings.ReplaceAll(output, "\n", "\r\n")
			writeAndRecord(conn, recorder, []byte(crlf))
		}

		writeAndRecord(conn, recorder, []byte(prompt()))
	}
}

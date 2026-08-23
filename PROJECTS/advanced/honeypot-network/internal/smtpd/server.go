/*
©AngelaMos | 2026
server.go

SMTP honeypot service accepting mail client connections

Emulates a Postfix-style mail server that accepts every AUTH
attempt as failed (capturing credentials in the process) and
every mail transaction, then rejects delivery so no real mail is
ever sent. Every command, credential attempt, and captured
message is published to the event bus for enrichment.
*/

package smtpd

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/CarterPerez-dev/hive/internal/config"
	"github.com/CarterPerez-dev/hive/internal/event"
	"github.com/CarterPerez-dev/hive/internal/ratelimit"
	"github.com/CarterPerez-dev/hive/internal/session"
	"github.com/CarterPerez-dev/hive/pkg/types"
)

type SMTPService struct {
	cfg     *config.Config
	bus     *event.Bus
	logger  zerolog.Logger
	tracker *session.Tracker
	limiter *ratelimit.IPLimiter
}

func New(
	cfg *config.Config,
	bus *event.Bus,
	logger *zerolog.Logger,
	tracker *session.Tracker,
	limiter *ratelimit.IPLimiter,
) *SMTPService {
	return &SMTPService{
		cfg:     cfg,
		bus:     bus,
		logger:  logger.With().Str("service", "smtp").Logger(),
		tracker: tracker,
		limiter: limiter,
	}
}

func (s *SMTPService) Name() string { return "smtp" }

func (s *SMTPService) Start(ctx context.Context) error {
	addr := s.cfg.Addr(s.cfg.SMTP.Port)

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("smtp listen %s: %w", addr, err)
	}

	s.logger.Info().
		Str("addr", addr).
		Msg("smtp honeypot listening")

	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	for ctx.Err() == nil {
		conn, err := listener.Accept()
		if err != nil {
			s.logger.Debug().Err(err).Msg("accept failed")
			continue
		}

		go s.handleConnection(ctx, conn)
	}

	return nil
}

func (s *SMTPService) handleConnection(
	ctx context.Context, conn net.Conn,
) {
	defer func() { _ = conn.Close() }()

	srcIP, srcPort := types.RemoteAddr(conn)
	if !s.limiter.Allow(srcIP) {
		return
	}

	sess := s.tracker.Start(
		s.cfg.Sensor.ID, types.ServiceSMTP,
		srcIP, srcPort, s.cfg.SMTP.Port,
	)
	defer s.tracker.End(sess.ID)

	s.publishConnect(sess, srcIP, srcPort)
	defer s.publishDisconnect(sess, srcIP, srcPort)

	_ = conn.SetDeadline(
		time.Now().Add(config.DefaultSessionTimeout),
	)

	sc := newSMTPConn(conn, s.cfg.SMTP.Banner, s.cfg.SMTP.Hostname)
	sc.greet()

	for {
		if ctx.Err() != nil {
			return
		}

		line, err := sc.readLine()
		if err != nil {
			return
		}

		result := sc.dispatch(line)

		if result.cmd != "" &&
			result.cmd != "DATA-LINE" &&
			result.cmd != "AUTH-CONT" {
			s.publishCommand(sess.ID, srcIP, result.cmd, result.arg)
		}

		if result.creds != nil {
			s.publishAuth(sess.ID, srcIP, result.creds)
			s.tracker.SetLogin(
				sess.ID, false, result.creds.username, "",
			)
		}

		if result.mail != nil {
			s.publishMessage(sess.ID, srcIP, result.mail)
			s.tracker.IncrCommandCount(sess.ID)
		}

		if result.quit {
			return
		}
	}
}

func (s *SMTPService) publishConnect(
	sess *types.Session, srcIP string, srcPort int,
) {
	s.bus.Publish(config.TopicConnect, &types.Event{
		ID:            uuid.Must(uuid.NewV7()).String(),
		SessionID:     sess.ID,
		SensorID:      s.cfg.Sensor.ID,
		Timestamp:     time.Now().UTC(),
		ServiceType:   types.ServiceSMTP,
		EventType:     types.EventConnect,
		SourceIP:      srcIP,
		SourcePort:    srcPort,
		DestPort:      s.cfg.SMTP.Port,
		Protocol:      types.ProtocolTCP,
		SchemaVersion: config.SchemaVersion,
	})
}

func (s *SMTPService) publishDisconnect(
	sess *types.Session, srcIP string, srcPort int,
) {
	s.bus.Publish(config.TopicDisconnect, &types.Event{
		ID:            uuid.Must(uuid.NewV7()).String(),
		SessionID:     sess.ID,
		SensorID:      s.cfg.Sensor.ID,
		Timestamp:     time.Now().UTC(),
		ServiceType:   types.ServiceSMTP,
		EventType:     types.EventDisconnect,
		SourceIP:      srcIP,
		SourcePort:    srcPort,
		DestPort:      s.cfg.SMTP.Port,
		Protocol:      types.ProtocolTCP,
		SchemaVersion: config.SchemaVersion,
	})
}

func (s *SMTPService) publishCommand(
	sessionID, srcIP, cmd, arg string,
) {
	serviceData, _ := json.Marshal(map[string]string{
		"command": cmd,
		"arg":     arg,
	})

	s.bus.Publish(config.TopicCommand, &types.Event{
		ID:            uuid.Must(uuid.NewV7()).String(),
		SessionID:     sessionID,
		SensorID:      s.cfg.Sensor.ID,
		Timestamp:     time.Now().UTC(),
		ServiceType:   types.ServiceSMTP,
		EventType:     types.EventCommand,
		SourceIP:      srcIP,
		Protocol:      types.ProtocolTCP,
		SchemaVersion: config.SchemaVersion,
		ServiceData:   serviceData,
	})
}

func (s *SMTPService) publishAuth(
	sessionID, srcIP string, creds *credResult,
) {
	serviceData, _ := json.Marshal(map[string]string{
		"username":    creds.username,
		"password":    creds.password,
		"auth_method": creds.method,
	})

	// Every credential attempt is logged as a failed login: the
	// honeypot never actually authenticates a mail client.
	s.bus.Publish(config.TopicAuth, &types.Event{
		ID:            uuid.Must(uuid.NewV7()).String(),
		SessionID:     sessionID,
		SensorID:      s.cfg.Sensor.ID,
		Timestamp:     time.Now().UTC(),
		ServiceType:   types.ServiceSMTP,
		EventType:     types.EventLoginFailed,
		SourceIP:      srcIP,
		Protocol:      types.ProtocolTCP,
		SchemaVersion: config.SchemaVersion,
		ServiceData:   serviceData,
	})
}

func (s *SMTPService) publishMessage(
	sessionID, srcIP string, mail *mailResult,
) {
	// "body" is intentionally the key name the IOC extractor already
	// scans (see internal/intel/ioc.go extractURLs), so any URLs in
	// the message body are picked up automatically as IOCs.
	serviceData, _ := json.Marshal(map[string]interface{}{
		"from": mail.from,
		"to":   mail.to,
		"body": mail.body,
		"size": len(mail.body),
	})

	s.bus.Publish(config.TopicFile, &types.Event{
		ID:            uuid.Must(uuid.NewV7()).String(),
		SessionID:     sessionID,
		SensorID:      s.cfg.Sensor.ID,
		Timestamp:     time.Now().UTC(),
		ServiceType:   types.ServiceSMTP,
		EventType:     types.EventFileUpload,
		SourceIP:      srcIP,
		Protocol:      types.ProtocolTCP,
		SchemaVersion: config.SchemaVersion,
		Tags:          []string{"smtp-message", "mitre:T1071"},
		ServiceData:   serviceData,
	})
}

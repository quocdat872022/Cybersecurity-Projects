/*
©AngelaMos | 2026
server.go

Telnet honeypot service accepting all authentication attempts

Emulates a Telnet-accessible Linux server. Performs minimal IAC
option negotiation, presents a login prompt, accepts any username/
password combination, and drops the attacker into the same fake
shell environment used by the SSH honeypot (FakeFS + DispatchCommand
from internal/sshd). Every connection, credential attempt, and
command is published to the event bus, and the full raw I/O is
recorded in asciicast v2 format for replay in the dashboard.
*/

package telnetd

import (
	"bufio"
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

const (
	termWidth  = 80
	termHeight = 24
)

type TelnetService struct {
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
) *TelnetService {
	return &TelnetService{
		cfg:     cfg,
		bus:     bus,
		logger:  logger.With().Str("service", "telnet").Logger(),
		tracker: tracker,
		limiter: limiter,
	}
}

func (s *TelnetService) Name() string { return "telnet" }

func (s *TelnetService) Start(ctx context.Context) error {
	addr := s.cfg.Addr(s.cfg.Telnet.Port)

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("telnet listen %s: %w", addr, err)
	}

	s.logger.Info().
		Str("addr", addr).
		Msg("telnet honeypot listening")

	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	for ctx.Err() == nil {
		conn, err := listener.Accept()
		if err != nil {
			s.logger.Debug().
				Err(err).Msg("accept failed")
			continue
		}

		go s.handleConnection(ctx, conn)
	}

	return nil
}

func (s *TelnetService) handleConnection(
	ctx context.Context, conn net.Conn,
) {
	defer func() { _ = conn.Close() }()

	srcIP, srcPort := types.RemoteAddr(conn)
	if !s.limiter.Allow(srcIP) {
		return
	}

	sess := s.tracker.Start(
		s.cfg.Sensor.ID, types.ServiceTelnet,
		srcIP, srcPort, s.cfg.Telnet.Port,
	)
	defer s.tracker.End(sess.ID)

	s.publishConnect(sess, srcIP, srcPort)
	defer s.publishDisconnect(sess, srcIP, srcPort)

	recorder := session.NewRecorder(
		sess.ID, srcIP, s.cfg.Sensor.ID,
		termWidth, termHeight,
	)

	_ = conn.SetDeadline(
		time.Now().Add(config.DefaultSessionTimeout),
	)

	negotiate(conn)

	reader := bufio.NewReader(newIACStrippingReader(conn))

	username, password, ok := s.promptLogin(
		conn, reader, recorder,
	)
	if !ok {
		return
	}

	s.publishAuth(sess.ID, srcIP, username, password)
	s.tracker.SetLogin(sess.ID, true, username, "telnet")

	s.runShell(
		ctx, conn, reader, sess, srcIP, username, recorder,
	)

	if _, err := recorder.Save(s.cfg.Log.ReplayDir); err != nil {
		s.logger.Error().Err(err).
			Str("session_id", sess.ID).
			Msg("failed to save telnet session recording")
	}
}

func (s *TelnetService) publishConnect(
	sess *types.Session, srcIP string, srcPort int,
) {
	s.bus.Publish(config.TopicConnect, &types.Event{
		ID:            uuid.Must(uuid.NewV7()).String(),
		SessionID:     sess.ID,
		SensorID:      s.cfg.Sensor.ID,
		Timestamp:     time.Now().UTC(),
		ServiceType:   types.ServiceTelnet,
		EventType:     types.EventConnect,
		SourceIP:      srcIP,
		SourcePort:    srcPort,
		DestPort:      s.cfg.Telnet.Port,
		Protocol:      types.ProtocolTCP,
		SchemaVersion: config.SchemaVersion,
	})
}

func (s *TelnetService) publishDisconnect(
	sess *types.Session, srcIP string, srcPort int,
) {
	s.bus.Publish(config.TopicDisconnect, &types.Event{
		ID:            uuid.Must(uuid.NewV7()).String(),
		SessionID:     sess.ID,
		SensorID:      s.cfg.Sensor.ID,
		Timestamp:     time.Now().UTC(),
		ServiceType:   types.ServiceTelnet,
		EventType:     types.EventDisconnect,
		SourceIP:      srcIP,
		SourcePort:    srcPort,
		DestPort:      s.cfg.Telnet.Port,
		Protocol:      types.ProtocolTCP,
		SchemaVersion: config.SchemaVersion,
	})
}

func (s *TelnetService) publishAuth(
	sessionID, srcIP, username, password string,
) {
	serviceData, _ := json.Marshal(map[string]string{
		"username":    username,
		"password":    password,
		"auth_method": "password",
	})

	s.bus.Publish(config.TopicAuth, &types.Event{
		ID:            uuid.Must(uuid.NewV7()).String(),
		SessionID:     sessionID,
		SensorID:      s.cfg.Sensor.ID,
		Timestamp:     time.Now().UTC(),
		ServiceType:   types.ServiceTelnet,
		EventType:     types.EventLoginSuccess,
		SourceIP:      srcIP,
		Protocol:      types.ProtocolTCP,
		SchemaVersion: config.SchemaVersion,
		ServiceData:   serviceData,
	})
}

func (s *TelnetService) publishCommand(
	sessionID, srcIP, cmd string,
) {
	serviceData, _ := json.Marshal(map[string]string{
		"command": cmd,
	})

	s.bus.Publish(config.TopicCommand, &types.Event{
		ID:            uuid.Must(uuid.NewV7()).String(),
		SessionID:     sessionID,
		SensorID:      s.cfg.Sensor.ID,
		Timestamp:     time.Now().UTC(),
		ServiceType:   types.ServiceTelnet,
		EventType:     types.EventCommand,
		SourceIP:      srcIP,
		Protocol:      types.ProtocolTCP,
		SchemaVersion: config.SchemaVersion,
		ServiceData:   serviceData,
	})
}

var _ types.Service = (*TelnetService)(nil)

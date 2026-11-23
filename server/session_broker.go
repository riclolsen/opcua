package server

import (
	mrand "math/rand"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/gopcua/opcua/ua"
)

type session struct {
	cfg sessionConfig

	ID                *ua.NodeID
	AuthTokenID       *ua.NodeID
	serverNonce       []byte
	remoteCertificate []byte

	PublishRequests chan PubReq

	// lastSeen is when the session was created or last used; guarded by
	// the broker's mu.
	lastSeen time.Time
}

type sessionConfig struct {
	sessionTimeout time.Duration
}

type sessionBroker struct {
	// mu protects concurrent modification of s
	mu sync.Mutex

	// s contains all sessions watched by the session broker
	s      map[string]*session
	logger Logger

	// clock returns the current time; time.Now when nil.
	clock func() time.Time
}

func newSessionBroker(logger Logger) *sessionBroker {
	return &sessionBroker{
		s:      make(map[string]*session),
		logger: logger,
	}
}

// NewSession creates a session that expires when it is not used for
// timeout (OPC 10000-4 §5.6.2: the server "shall close the Session" when the
// client sends no request within the revised session timeout).
func (sb *sessionBroker) NewSession(timeout time.Duration) *session {
	s := &session{
		ID:              ua.NewGUIDNodeID(1, uuid.New().String()),
		AuthTokenID:     ua.NewNumericNodeID(0, uint32(mrand.Int31())),
		PublishRequests: make(chan PubReq, 100),
		cfg:             sessionConfig{sessionTimeout: timeout},
		lastSeen:        sb.now(),
	}

	sb.mu.Lock()
	sb.sweepLocked()
	sb.s[s.AuthTokenID.String()] = s
	sb.mu.Unlock()

	return s
}

// Count returns the number of sessions, after removing the expired ones,
// so that abandoned sessions do not count against a session limit.
func (sb *sessionBroker) Count() int {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	sb.sweepLocked()
	return len(sb.s)
}

// sweepLocked removes the expired sessions. The caller holds mu.
func (sb *sessionBroker) sweepLocked() {
	now := sb.now()
	for k, s := range sb.s {
		if s.expired(now) {
			delete(sb.s, k)
		}
	}
}

// Touch records a request for the session of authToken, if any.
func (sb *sessionBroker) Touch(authToken *ua.NodeID) {
	if authToken == nil {
		return
	}
	sb.mu.Lock()
	defer sb.mu.Unlock()
	if s := sb.s[authToken.String()]; s != nil && !s.expired(sb.now()) {
		s.lastSeen = sb.now()
	}
}

func (sb *sessionBroker) now() time.Time {
	if sb.clock != nil {
		return sb.clock()
	}
	return time.Now()
}

func (s *session) expired(now time.Time) bool {
	return s.cfg.sessionTimeout > 0 && now.Sub(s.lastSeen) > s.cfg.sessionTimeout
}

func (sb *sessionBroker) Close(authToken *ua.NodeID) error {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	if sb.s[authToken.String()] == nil {
		if sb.logger != nil {
			sb.logger.Warn("sessionBroker.Close: error looking up session %v", authToken)
		}
	}
	delete(sb.s, authToken.String())

	return nil
}

func (sb *sessionBroker) Session(authToken *ua.NodeID) *session {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	s := sb.s[authToken.String()]
	if s != nil && s.expired(sb.now()) {
		delete(sb.s, authToken.String())
		s = nil
	}
	if s == nil {
		if sb.logger != nil {
			sb.logger.Warn("sessionBroker.Session: error looking up session %v", authToken)
		}
	}

	return s
}

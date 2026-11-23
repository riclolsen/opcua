// Copyright 2018-2026 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package uacp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"github.com/gopcua/opcua/debug"
	"github.com/gopcua/opcua/secevent"
	"github.com/gopcua/opcua/ua"
)

const (
	// DefaultHandshakeTimeout bounds the time a peer has, after its TCP
	// connection is accepted, to complete the Hello/Acknowledge handshake.
	DefaultHandshakeTimeout = 10 * time.Second

	// DefaultMaxPendingHandshakes bounds the number of connections that are
	// accepted but have not completed the handshake, or have completed it
	// and wait for Accept.
	DefaultMaxPendingHandshakes = 128
)

// DefaultConnectionRateLimit is the per IP address connection rate above
// which a listener reports a secevent.ConnectionFlood. It is not enforced.
var DefaultConnectionRateLimit = secevent.RateLimit{Max: 50, Window: 10 * time.Second}

// ListenOption configures a Listener.
type ListenOption func(*listenConfig)

type listenConfig struct {
	events           secevent.Handler
	handshakeTimeout time.Duration
	maxPending       int
	maxConns         int
	maxConnsPerIP    int
	connRate         secevent.RateLimit
	allowed          []netip.Prefix
	lookupMAC        bool
}

// WithEventHandler sets the handler for the security events of the listener
// and of the connections it accepts.
func WithEventHandler(h secevent.Handler) ListenOption {
	return func(c *listenConfig) { c.events = h }
}

// WithHandshakeTimeout sets how long a peer has to complete the
// Hello/Acknowledge handshake. A peer that connects and stays silent is
// disconnected after d. d <= 0 selects DefaultHandshakeTimeout.
func WithHandshakeTimeout(d time.Duration) ListenOption {
	return func(c *listenConfig) {
		if d <= 0 {
			d = DefaultHandshakeTimeout
		}
		c.handshakeTimeout = d
	}
}

// WithMaxPendingHandshakes bounds the connections in the handshake. A
// connection beyond the bound is refused with Bad_TcpServerTooBusy.
// n <= 0 selects DefaultMaxPendingHandshakes.
func WithMaxPendingHandshakes(n int) ListenOption {
	return func(c *listenConfig) {
		if n <= 0 {
			n = DefaultMaxPendingHandshakes
		}
		c.maxPending = n
	}
}

// WithMaxConnections bounds the open connections of the listener, in total
// and per peer IP address. A connection beyond a bound is refused with
// Bad_TcpServerTooBusy and reported as secevent.ConnectionLimit. A bound
// <= 0 disables it.
func WithMaxConnections(total, perIP int) ListenOption {
	return func(c *listenConfig) {
		c.maxConns = total
		c.maxConnsPerIP = perIP
	}
}

// WithConnectionRateLimit sets the per IP address connection rate above
// which a secevent.ConnectionFlood is reported, and, if l.Enforce is set,
// further connections are refused until the window ends.
func WithConnectionRateLimit(l secevent.RateLimit) ListenOption {
	return func(c *listenConfig) { c.connRate = l }
}

// WithAllowedPeers restricts the peers that may connect to those whose IP
// address is in one of prefixes. Other connections are closed right after
// they are accepted and reported as secevent.ConnectionRejected. Without
// this option every peer may connect.
func WithAllowedPeers(prefixes ...netip.Prefix) ListenOption {
	return func(c *listenConfig) { c.allowed = append(c.allowed, prefixes...) }
}

// WithMACLookup enables or disables the lookup of the peer's MAC address
// for every accepted connection. It is enabled by default and only done
// when an event handler is set or Conn.RemoteMAC is called.
func WithMACLookup(b bool) ListenOption {
	return func(c *listenConfig) { c.lookupMAC = b }
}

// Listener is a OPC UA Connection Protocol network listener.
//
// It performs the Hello/Acknowledge handshake of each accepted connection on
// a goroutine of its own, bounded by a timeout, so that a peer that connects
// and does not speak cannot hold up other connections.
type Listener struct {
	l        *net.TCPListener
	ack      *Acknowledge
	endpoint string
	cfg      listenConfig

	macs     *secevent.MACTracker
	connRate *secevent.Counter
	// reports suppresses repeated refusal events for the same reason and
	// peer, so that a flood does not turn into an event flood.
	reports *secevent.Counter
	pending chan struct{}

	mu     sync.Mutex
	active int
	perIP  map[netip.Addr]int

	startOnce sync.Once
	ready     chan *Conn
	done      chan struct{}
	closeOnce sync.Once
	failed    chan struct{}
	acceptErr error
}

// Listen acts like net.Listen for OPC UA Connection Protocol networks.
//
// Currently the endpoint can only be specified in "opc.tcp://<addr[:port]>/path" format.
//
// If the IP field of laddr is nil or an unspecified IP address, Listen listens
// on all available unicast and anycast IP addresses of the local system.
// If the Port field of laddr is 0, a port number is automatically chosen.
func Listen(ctx context.Context, endpoint string, ack *Acknowledge, opts ...ListenOption) (*Listener, error) {
	if ack == nil {
		ack = DefaultServerACK
	}
	_, laddr, err := ResolveEndpoint(ctx, endpoint)
	if err != nil {
		return nil, err
	}

	cfg := listenConfig{
		handshakeTimeout: DefaultHandshakeTimeout,
		maxPending:       DefaultMaxPendingHandshakes,
		connRate:         DefaultConnectionRateLimit,
		lookupMAC:        true,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	var lc net.ListenConfig
	l, err := lc.Listen(ctx, "tcp", laddr.Host)
	if err != nil {
		return nil, err
	}
	return &Listener{
		l:        l.(*net.TCPListener),
		ack:      ack,
		endpoint: endpoint,
		cfg:      cfg,
		macs:     secevent.NewMACTracker(),
		connRate: secevent.NewCounter(cfg.connRate),
		reports:  secevent.NewCounter(secevent.RateLimit{Max: 1, Window: time.Second}),
		pending:  make(chan struct{}, cfg.maxPending),
		perIP:    make(map[netip.Addr]int),
		ready:    make(chan *Conn),
		done:     make(chan struct{}),
		failed:   make(chan struct{}),
	}, nil
}

// Accept returns the next connection that completed the Hello/Acknowledge
// handshake. Connections that fail admission control or the handshake are
// closed, reported to the event handler, and not returned; Accept returns an
// error only when the listener fails or is closed, or ctx ends.
func (l *Listener) Accept(ctx context.Context) (*Conn, error) {
	l.startOnce.Do(func() { go l.acceptLoop() })
	select {
	case c := <-l.ready:
		return c, nil
	case <-l.failed:
		return nil, l.acceptErr
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Close closes the Listener. Connections still in the handshake are closed
// when their handshake ends;
// connections already returned by Accept are not.
func (l *Listener) Close() error {
	l.closeOnce.Do(func() { close(l.done) })
	return l.l.Close()
}

// Addr returns the listener's network address.
func (l *Listener) Addr() net.Addr {
	return l.l.Addr()
}

// Endpoint returns the listener's EndpointURL.
func (l *Listener) Endpoint() string {
	return l.endpoint
}

// EventHandler returns the listener's event handler, which may be nil.
func (l *Listener) EventHandler() secevent.Handler {
	return l.cfg.events
}

func (l *Listener) emit(e secevent.Event) {
	if e.Local == nil {
		e.Local = l.l.Addr()
	}
	l.cfg.events.Emit(e)
}

// emitRefusal reports a refused connection at most once per second per
// reason and peer.
func (l *Listener) emitRefusal(e secevent.Event, ip netip.Addr) {
	if l.cfg.events == nil {
		return
	}
	if suppressed, _ := l.reports.Hit(string(e.Kind)+"/"+ip.String(), time.Now()); suppressed {
		return
	}
	l.emit(e)
}

func (l *Listener) acceptLoop() {
	var delay time.Duration
	for {
		c, err := l.l.AcceptTCP()
		if err != nil {
			select {
			case <-l.done:
				l.fail(err)
				return
			default:
			}
			if errors.Is(err, syscall.EMFILE) || errors.Is(err, syscall.ENFILE) {
				l.emitRefusal(secevent.Event{
					Kind:     secevent.ConnectionLimit,
					Severity: secevent.Alert,
					Detail:   "out of file descriptors while accepting connections",
					Err:      err,
				}, netip.Addr{})
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() || isTemporary(err) {
				// Back off like net/http does, instead of spinning.
				if delay == 0 {
					delay = 5 * time.Millisecond
				} else if delay *= 2; delay > time.Second {
					delay = time.Second
				}
				select {
				case <-time.After(delay):
				case <-l.done:
					l.fail(err)
					return
				}
				continue
			}
			l.fail(err)
			return
		}
		delay = 0

		select {
		case l.pending <- struct{}{}:
		default:
			ip := addrOf(c.RemoteAddr())
			l.emitRefusal(secevent.Event{
				Kind:     secevent.ConnectionLimit,
				Severity: secevent.Alert,
				Remote:   c.RemoteAddr(),
				Status:   ua.StatusBadTCPServerTooBusy,
				Detail:   fmt.Sprintf("%d connections pending handshake", cap(l.pending)),
			}, ip)
			refuse(c, ua.StatusBadTCPServerTooBusy)
			continue
		}
		go l.serve(c)
	}
}

func isTemporary(err error) bool {
	t, ok := err.(interface{ Temporary() bool })
	return ok && t.Temporary()
}

func (l *Listener) fail(err error) {
	l.acceptErr = err
	close(l.failed)
}

func addrOf(a net.Addr) netip.Addr {
	if ta, ok := a.(*net.TCPAddr); ok {
		if ip, ok := netip.AddrFromSlice(ta.IP); ok {
			return ip.Unmap()
		}
	}
	return netip.Addr{}
}

// refuse sends an ERR message with code to a connection that has not
// completed the handshake and closes it. The write is bounded so that a
// peer that does not read cannot hold the goroutine.
func refuse(c *net.TCPConn, code ua.StatusCode) {
	_ = c.SetWriteDeadline(time.Now().Add(time.Second))
	if b, err := encodeError(code); err == nil {
		_, _ = c.Write(b)
	}
	_ = c.Close()
}

func encodeError(code ua.StatusCode) ([]byte, error) {
	body, err := ua.Encode(&Error{ErrorCode: uint32(code)})
	if err != nil {
		return nil, err
	}
	h := Header{MessageType: "ERR", ChunkType: 'F', MessageSize: uint32(len(body) + hdrlen)}
	hdr, err := h.Encode()
	if err != nil {
		return nil, err
	}
	return append(hdr, body...), nil
}

func (l *Listener) allowed(ip netip.Addr) bool {
	if len(l.cfg.allowed) == 0 {
		return true
	}
	for _, p := range l.cfg.allowed {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// reserve takes a connection slot for ip, or reports which limit is
// reached.
func (l *Listener) reserve(ip netip.Addr) (ok bool, reason string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.cfg.maxConns > 0 && l.active >= l.cfg.maxConns {
		return false, fmt.Sprintf("%d open connections, the maximum", l.active)
	}
	if l.cfg.maxConnsPerIP > 0 && l.perIP[ip] >= l.cfg.maxConnsPerIP {
		return false, fmt.Sprintf("%d open connections from %s, the maximum per address", l.perIP[ip], ip)
	}
	l.active++
	l.perIP[ip]++
	return true, ""
}

func (l *Listener) releaseSlot(ip netip.Addr) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.active--
	if l.perIP[ip]--; l.perIP[ip] <= 0 {
		delete(l.perIP, ip)
	}
}

// serve runs admission control and the handshake of one accepted
// connection, and hands it to Accept.
func (l *Listener) serve(c *net.TCPConn) {
	defer func() { <-l.pending }()

	remote := c.RemoteAddr()
	ip := addrOf(remote)
	now := time.Now()

	var mac net.HardwareAddr
	var macErr error = secevent.ErrMACUnavailable
	if l.cfg.lookupMAC && l.cfg.events != nil {
		mac, macErr = secevent.LookupAddrMAC(remote)
	}
	base := secevent.Event{Remote: remote, RemoteMAC: mac}

	ev := base
	ev.Kind, ev.Severity = secevent.ConnectionAccepted, secevent.Info
	l.emit(ev)

	if mac != nil {
		if prev, changed := l.macs.Observe(ip.AsSlice(), mac); changed {
			ev := base
			ev.Kind, ev.Severity, ev.PreviousMAC = secevent.MACChanged, secevent.Alert, prev
			ev.Detail = "peer IP address seen with a different MAC address"
			l.emit(ev)
		}
	}

	if !l.allowed(ip) {
		ev := base
		ev.Kind, ev.Severity = secevent.ConnectionRejected, secevent.Warning
		ev.Detail = "peer address not in the allowed networks"
		l.emitRefusal(ev, ip)
		_ = c.Close()
		return
	}

	if exceeded, first := l.connRate.Hit(ip.String(), now); exceeded {
		if first {
			ev := base
			ev.Kind, ev.Severity = secevent.ConnectionFlood, secevent.Alert
			lim := l.connRate.Limit()
			ev.Detail = fmt.Sprintf("more than %d connections in %s", lim.Max, lim.Window)
			l.emit(ev)
		}
		if l.connRate.Limit().Enforce {
			refuse(c, ua.StatusBadTCPServerTooBusy)
			return
		}
	}

	if ok, reason := l.reserve(ip); !ok {
		ev := base
		ev.Kind, ev.Severity, ev.Status = secevent.ConnectionLimit, secevent.Alert, ua.StatusBadTCPServerTooBusy
		ev.Detail = reason
		l.emitRefusal(ev, ip)
		refuse(c, ua.StatusBadTCPServerTooBusy)
		return
	}

	conn := &Conn{
		TCPConn: c,
		id:      nextid(),
		ack:     l.ack,
		events:  l.cfg.events,
		release: func() { l.releaseSlot(ip) },
	}
	if l.cfg.lookupMAC && l.cfg.events != nil {
		// Reuse the lookup done for the admission events.
		conn.mac, conn.macErr = mac, macErr
		conn.macOnce.Do(func() {})
	}

	deadline := time.Now().Add(l.cfg.handshakeTimeout)
	_ = conn.SetDeadline(deadline)
	err := conn.srvhandshake(l.endpoint, deadline)
	// conn, not c: a ReverseHello replaces the socket.
	_ = conn.SetDeadline(time.Time{})
	if err != nil {
		debug.Printf("uacp %d: handshake failed: %v", conn.id, err)
		ev := secevent.Event{Kind: secevent.HandshakeFailed, Severity: secevent.Warning, Err: err}
		var ne net.Error
		switch {
		case errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF):
			ev.Detail = "connection closed before the handshake completed"
		case errors.As(err, &ne) && ne.Timeout():
			ev.Detail = fmt.Sprintf("no handshake within %s", l.cfg.handshakeTimeout)
		}
		conn.Emit(ev)
		conn.Close()
		return
	}

	select {
	case l.ready <- conn:
	case <-l.done:
		conn.Close()
	}
}

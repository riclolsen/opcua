// Copyright 2018-2020 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package uacp

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gopcua/opcua/debug"
	"github.com/gopcua/opcua/errors"
	"github.com/gopcua/opcua/secevent"
	"github.com/gopcua/opcua/ua"
)

const (
	KB = 1024
	MB = 1024 * KB

	DefaultReceiveBufSize = 0xffff
	DefaultSendBufSize    = 0xffff
	DefaultMaxChunkCount  = 512
	DefaultMaxMessageSize = 2 * MB
)

var (
	// DefaultClientACK is the ACK handshake message sent to the server
	// for client connections.
	DefaultClientACK = &Acknowledge{
		ReceiveBufSize: DefaultReceiveBufSize,
		SendBufSize:    DefaultSendBufSize,
		MaxChunkCount:  0, // use what the server wants
		MaxMessageSize: 0, // use what the server wants
	}

	// DefaultServerACK is the ACK handshake message sent to the client
	// for server connections.
	DefaultServerACK = &Acknowledge{
		ReceiveBufSize: DefaultReceiveBufSize,
		SendBufSize:    DefaultSendBufSize,
		MaxChunkCount:  DefaultMaxChunkCount,
		MaxMessageSize: DefaultMaxMessageSize,
	}
)

// connid stores the current connection id. updated with atomic.AddUint32
var connid uint32

// nextid returns the next connection id
func nextid() uint32 {
	return atomic.AddUint32(&connid, 1)
}

// Dialer establishes a connection to an endpoint.
type Dialer struct {
	// Dialer establishes the TCP connection. Defaults to net.Dialer.
	Dialer *net.Dialer

	// ClientACK defines the connection parameters requested by the client.
	// Defaults to DefaultClientACK.
	ClientACK *Acknowledge

	// Events receives the security events of the connections the dialer
	// establishes. Optional.
	Events secevent.Handler

	// MACs, when set together with Events, remembers the MAC address of
	// every server the dialer connects to and reports a
	// secevent.MACChanged event when a later connection to the same IP
	// address reaches a different MAC address.
	MACs *secevent.MACTracker
}

func (d *Dialer) Dial(ctx context.Context, endpoint string) (*Conn, error) {
	debug.Printf("uacp: connecting to %s", endpoint)

	// Dial the host as written, not one address resolved up front: for a
	// name, net.Dialer tries every address it resolves to, in order, so a
	// name whose first address does not answer (localhost resolving to an
	// IPv6 ::1 the server does not listen on) still reaches the server on
	// the next one.
	_, raddr, err := parseEndpoint(endpoint)
	if err != nil {
		return nil, err
	}

	dl := d.Dialer
	if dl == nil {
		dl = &net.Dialer{}
	}

	c, err := dl.DialContext(ctx, "tcp", raddr.Host)
	if err != nil {
		return nil, err
	}

	conn, err := NewConn(c.(*net.TCPConn), d.ClientACK)
	if err != nil {
		c.Close()
		return nil, err
	}
	conn.events = d.Events
	if d.Events != nil && d.MACs != nil {
		if mac, err := conn.RemoteMAC(); err == nil {
			if prev, changed := d.MACs.Observe(conn.TCPConn.RemoteAddr().(*net.TCPAddr).IP, mac); changed {
				conn.Emit(secevent.Event{
					Kind:        secevent.MACChanged,
					Severity:    secevent.Alert,
					PreviousMAC: prev,
					Detail:      "server IP address reached through a different MAC address",
				})
			}
		}
	}

	debug.Printf("uacp %d: start HEL/ACK handshake", conn.id)
	if err := conn.Handshake(ctx, endpoint); err != nil {
		debug.Printf("uacp %d: HEL/ACK handshake failed: %s", conn.id, err)
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// Dial uses the default dialer to establish a connection to the endpoint
func Dial(ctx context.Context, endpoint string) (*Conn, error) {
	d := &Dialer{}
	return d.Dial(ctx, endpoint)
}

type Conn struct {
	*net.TCPConn
	id  uint32
	ack *Acknowledge

	// events receives the security events of the connection.
	events secevent.Handler

	// mac caches the result of the MAC address lookup of the peer.
	macOnce sync.Once
	mac     net.HardwareAddr
	macErr  error

	// release is called once when the connection closes, to return its
	// slot to the listener's connection limits.
	release func()

	closeOnce sync.Once
}

func NewConn(c *net.TCPConn, ack *Acknowledge) (*Conn, error) {
	if c == nil {
		return nil, fmt.Errorf("no connection")
	}
	if ack == nil {
		ack = DefaultClientACK
	}
	return &Conn{TCPConn: c, id: nextid(), ack: ack}, nil
}

func (c *Conn) ID() uint32 {
	return c.id
}

func (c *Conn) ReceiveBufSize() uint32 {
	return c.ack.ReceiveBufSize
}

func (c *Conn) SendBufSize() uint32 {
	return c.ack.SendBufSize
}

func (c *Conn) MaxMessageSize() uint32 {
	return c.ack.MaxMessageSize
}

func (c *Conn) MaxChunkCount() uint32 {
	return c.ack.MaxChunkCount
}

func (c *Conn) Close() (err error) {
	err = io.EOF
	c.closeOnce.Do(func() { err = c.close() })
	return err
}

func (c *Conn) close() error {
	debug.Printf("uacp %d: close", c.id)
	if c.release != nil {
		c.release()
	}
	return c.TCPConn.Close()
}

// SetEventHandler sets the handler for the security events of the
// connection. It must be called before the connection is used.
func (c *Conn) SetEventHandler(h secevent.Handler) {
	c.events = h
}

// EventHandler returns the handler for the security events of the
// connection, which may be nil.
func (c *Conn) EventHandler() secevent.Handler {
	return c.events
}

// RemoteMAC returns the MAC address of the peer, looked up in the operating
// system's neighbor table once per connection. It returns
// secevent.ErrMACUnavailable when the peer is not on a directly attached
// network or the platform does not support the lookup.
func (c *Conn) RemoteMAC() (net.HardwareAddr, error) {
	c.macOnce.Do(func() {
		if c.mac == nil && c.macErr == nil {
			c.mac, c.macErr = secevent.LookupAddrMAC(c.TCPConn.RemoteAddr())
		}
	})
	return c.mac, c.macErr
}

// Emit reports a security event of the connection, filling in the
// addresses, the MAC address of the peer and the connection id. It is a
// no-op when the connection has no event handler.
func (c *Conn) Emit(e secevent.Event) {
	if c == nil || c.events == nil {
		return
	}
	if e.Local == nil {
		e.Local = c.TCPConn.LocalAddr()
	}
	if e.Remote == nil {
		e.Remote = c.TCPConn.RemoteAddr()
	}
	if e.RemoteMAC == nil {
		e.RemoteMAC, _ = c.RemoteMAC()
	}
	if e.ConnID == 0 {
		e.ConnID = c.id
	}
	c.events.Emit(e)
}

// Handshake sends Hello and waits for Acknowledge, bounded by ctx: by its
// deadline, and by its cancellation. The reconnect monitor dials with a
// ctx that is cancelled on Client.Close but has no deadline; a server that
// accepts the TCP connection and never answers Hello would otherwise hold
// the read — and the monitor goroutine and its socket — past Close.
func (c *Conn) Handshake(ctx context.Context, endpoint string) error {
	stop := context.AfterFunc(ctx, func() {
		// A deadline in the past unblocks the pending read or write.
		_ = c.SetDeadline(time.Unix(1, 0))
	})
	err := c.handshake(ctx, endpoint)
	if !stop() {
		// ctx ended during the exchange. Whatever it returned, the
		// connection's deadline is now in the past: report why.
		return ctx.Err()
	}
	return err
}

func (c *Conn) handshake(ctx context.Context, endpoint string) error {
	hel := &Hello{
		Version:        c.ack.Version,
		ReceiveBufSize: c.ack.ReceiveBufSize,
		SendBufSize:    c.ack.SendBufSize,
		MaxMessageSize: c.ack.MaxMessageSize,
		MaxChunkCount:  c.ack.MaxChunkCount,
		EndpointURL:    endpoint,
	}

	// set a deadline if there is one
	if dl, ok := ctx.Deadline(); ok {
		c.SetDeadline(dl)
	}

	if err := c.Send("HELF", hel); err != nil {
		return err
	}

	b, err := c.Receive()
	if err != nil {
		return err
	}

	// clear the deadline
	c.SetDeadline(time.Time{})

	msgtyp := string(b[:4])
	switch msgtyp {
	case "ACKF":
		ack := new(Acknowledge)
		if _, err := ack.Decode(b[hdrlen:]); err != nil {
			return errors.Errorf("uacp: decode ACK failed: %s", err)
		}
		if ack.Version != 0 {
			return errors.Errorf("uacp: invalid version %d", ack.Version)
		}
		if ack.MaxChunkCount == 0 {
			ack.MaxChunkCount = DefaultMaxChunkCount
			debug.Printf("uacp %d: server has no chunk limit. Using %d", c.id, ack.MaxChunkCount)
		}
		if ack.MaxMessageSize == 0 {
			ack.MaxMessageSize = DefaultMaxMessageSize
			debug.Printf("uacp %d: server has no message size limit. Using %d", c.id, ack.MaxMessageSize)
		}
		c.ack = ack
		debug.Printf("uacp %d: recv %#v", c.id, ack)
		return nil

	case "ERRF":
		errf := new(Error)
		if _, err := errf.Decode(b[hdrlen:]); err != nil {
			return errors.Errorf("uacp: decode ERR failed: %s", err)
		}
		debug.Printf("uacp %d: recv %#v", c.id, errf)
		return errf

	default:
		c.SendError(ua.StatusBadTCPInternalError)
		return errors.Errorf("invalid handshake packet %q", msgtyp)
	}
}

// srvhandshake runs the server side of the handshake. deadline bounds the
// whole handshake, including the connection a ReverseHello asks for.
func (c *Conn) srvhandshake(endpoint string, deadline time.Time) error {
	b, err := c.Receive()
	if err != nil {
		c.SendError(ua.StatusBadTCPInternalError)
		return err
	}

	// HEL or RHE?
	msgtyp := string(b[:4])
	msg := b[hdrlen:]
	switch msgtyp {
	case "HELF":
		hel := new(Hello)
		if _, err := hel.Decode(msg); err != nil {
			c.Emit(secevent.Event{Kind: secevent.MalformedMessage, Severity: secevent.Warning, Detail: "invalid Hello", Err: err})
			c.SendError(ua.StatusBadTCPInternalError)
			return err
		}
		// OPC 10000-6 §7.1.2.3: the EndpointUrl "shall be less than 4096
		// bytes"; a server rejects a longer one with
		// Bad_TcpEndpointUrlInvalid.
		if len(hel.EndpointURL) >= maxEndpointURLLength {
			c.Emit(secevent.Event{Kind: secevent.MalformedMessage, Severity: secevent.Warning, Status: ua.StatusBadTCPEndpointURLInvalid, Detail: fmt.Sprintf("Hello EndpointUrl of %d bytes", len(hel.EndpointURL))})
			c.SendError(ua.StatusBadTCPEndpointURLInvalid)
			return errors.Errorf("uacp: endpoint url too long: %d bytes", len(hel.EndpointURL))
		}
		// TODO (dh): Temporarily disabled until a proper fix can be implemented.
		// Problem is that when listening on a random port, (eg. :0), this check fails
		//if hel.EndpointURL != endpoint {
		//	c.SendError(ua.StatusBadTCPEndpointURLInvalid)
		//	return fmt.Errorf("uacp: invalid endpoint url %s", hel.EndpointURL)
		//}
		if err := c.Send("ACKF", c.ack); err != nil {
			c.SendError(ua.StatusBadTCPInternalError)
			return err
		}
		debug.Printf("uacp %d: recv %#v", c.id, hel)
		return nil

	case "RHEF":
		rhe := new(ReverseHello)
		if _, err := rhe.Decode(msg); err != nil {
			c.Emit(secevent.Event{Kind: secevent.MalformedMessage, Severity: secevent.Warning, Detail: "invalid ReverseHello", Err: err})
			c.SendError(ua.StatusBadTCPInternalError)
			return err
		}
		c.Emit(secevent.Event{Kind: secevent.ReverseHello, Severity: secevent.Notice, Detail: fmt.Sprintf("ReverseHello from ServerUri %q for EndpointUrl %q", rhe.ServerURI, rhe.EndpointURL)})
		if rhe.EndpointURL != endpoint {
			c.SendError(ua.StatusBadTCPEndpointURLInvalid)
			return errors.Errorf("uacp: invalid endpoint url %s", rhe.EndpointURL)
		}
		debug.Printf("uacp %d: connecting to %s", c.id, rhe.ServerURI)
		// Close the socket only: Close would mark the Conn closed and
		// release its listener slot while it carries on over c2.
		c.TCPConn.Close()
		dialer := net.Dialer{Deadline: deadline}
		c2, err := dialer.DialContext(context.Background(), "tcp", rhe.ServerURI)
		if err != nil {
			return err
		}
		c.TCPConn = c2.(*net.TCPConn)
		// The peer is now another host: forget the MAC address looked up
		// for the old one.
		c.macOnce = sync.Once{}
		c.mac, c.macErr = nil, nil
		debug.Printf("uacp %d: recv %#v", c.id, rhe)
		return nil

	case "ERRF":
		errf := new(Error)
		if _, err := errf.Decode(b[hdrlen:]); err != nil {
			return errors.Errorf("uacp: decode ERR failed: %s", err)
		}
		debug.Printf("uacp %d: recv %#v", c.id, errf)
		return errf

	default:
		c.SendError(ua.StatusBadTCPInternalError)
		return errors.Errorf("invalid handshake packet %q", msgtyp)
	}
}

// hdrlen is the size of the uacp header
const hdrlen = 8

// maxEndpointURLLength bounds the EndpointUrl of a Hello, which "shall be
// less than 4096 bytes"
// (OPC 10000-6 §7.1.2.3).
const maxEndpointURLLength = 4096

// Receive reads a full UACP message from the underlying connection.
// The size of b must be at least ReceiveBufSize. Otherwise,
// the function returns an error.
func (c *Conn) Receive() ([]byte, error) {
	// TODO(kung-foo): allow user-specified buffer
	// TODO(kung-foo): sync.Pool
	b := make([]byte, c.ack.ReceiveBufSize)

	if _, err := io.ReadFull(c, b[:hdrlen]); err != nil {
		// todo(fs): do not wrap this error since it hides io.EOF
		// todo(fs): use golang.org/x/xerrors
		return nil, err
	}

	var h Header
	if _, err := h.Decode(b[:hdrlen]); err != nil {
		err = errors.Errorf("uacp: header decode failed: %s", err)
		c.Emit(secevent.Event{Kind: secevent.MalformedMessage, Severity: secevent.Warning, Detail: "invalid uacp header", Err: err})
		return nil, err
	}

	if !validMessageType(h.MessageType, h.ChunkType) {
		err := errors.Errorf("uacp: invalid message type %q, chunk type %q: %w", h.MessageType, h.ChunkType, ua.StatusBadTCPMessageTypeInvalid)
		c.Emit(secevent.Event{Kind: secevent.MalformedMessage, Severity: secevent.Warning, Status: ua.StatusBadTCPMessageTypeInvalid, Detail: "invalid message type", Err: err})
		return nil, err
	}

	if h.MessageSize > c.ack.ReceiveBufSize {
		err := errors.Errorf("uacp: message too large: %d > %d bytes. MsgType=%s, ChunkType=%c", h.MessageSize, c.ack.ReceiveBufSize, h.MessageType, h.ChunkType)
		c.Emit(secevent.Event{Kind: secevent.OversizedMessage, Severity: secevent.Warning, Status: ua.StatusBadTCPMessageTooLarge, Detail: fmt.Sprintf("message of %d bytes exceeds receive buffer of %d bytes", h.MessageSize, c.ack.ReceiveBufSize), Err: err})
		return nil, err
	}
	if h.MessageSize < hdrlen {
		err := errors.Errorf("uacp: message too small: %d bytes. MsgType=%s, ChunkType=%c.", h.MessageSize, h.MessageType, h.ChunkType)
		c.Emit(secevent.Event{Kind: secevent.MalformedMessage, Severity: secevent.Warning, Detail: "message size smaller than header", Err: err})
		return nil, err
	}

	if _, err := io.ReadFull(c, b[hdrlen:h.MessageSize]); err != nil {
		// todo(fs): do not wrap this error since it hides io.EOF
		// todo(fs): use golang.org/x/xerrors
		return nil, err
	}

	debug.Printf("uacp %d: recv %s%c with %d bytes", c.id, h.MessageType, h.ChunkType, h.MessageSize)

	if h.MessageType == "ERR" {
		errf := new(Error)
		if _, err := errf.Decode(b[hdrlen:h.MessageSize]); err != nil {
			err = errors.Errorf("uacp: failed to decode ERRF message: %s", err)
			c.Emit(secevent.Event{Kind: secevent.MalformedMessage, Severity: secevent.Warning, Detail: "invalid ERR message", Err: err})
			return nil, err
		}
		return nil, errf
	}
	return b[:h.MessageSize], nil
}

// validMessageType reports whether typ and chunk form a message type of
// OPC 10000-6 §7.1.2 and §6.7.2: the connection protocol messages are
// single, final chunks; the secure conversation messages are final ('F'),
// intermediate ('C') or abort ('A') chunks.
func validMessageType(typ string, chunk byte) bool {
	switch typ {
	case "HEL", "ACK", "ERR", "RHE":
		return chunk == 'F'
	case "MSG", "OPN", "CLO":
		return chunk == 'F' || chunk == 'C' || chunk == 'A'
	}
	return false
}

func (c *Conn) Send(typ string, msg interface{}) error {
	if len(typ) != 4 {
		return errors.Errorf("invalid msg type: %s", typ)
	}

	body, err := ua.Encode(msg)
	if err != nil {
		return errors.Errorf("encode msg failed: %s", err)
	}

	h := Header{
		MessageType: typ[:3],
		ChunkType:   typ[3],
		MessageSize: uint32(len(body) + hdrlen),
	}

	if h.MessageSize > c.ack.SendBufSize {
		return errors.Errorf("send packet too large: %d > %d bytes", h.MessageSize, c.ack.SendBufSize)
	}

	hdr, err := h.Encode()
	if err != nil {
		return errors.Errorf("encode hdr failed: %s", err)
	}

	b := append(hdr, body...)
	if _, err := c.Write(b); err != nil {
		return errors.Errorf("write failed: %s", err)
	}
	debug.Printf("uacp %d: sent %s with %d bytes", c.id, typ, len(b))

	return nil
}

func (c *Conn) SendError(code ua.StatusCode) {
	// we swallow the error to silence complaints from the linter
	// since sending an error will close the connection and we
	// want to bubble a different error up.
	_ = c.Send("ERRF", &Error{ErrorCode: uint32(code)})
}

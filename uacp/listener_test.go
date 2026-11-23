// Copyright 2018-2026 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package uacp

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/gopcua/opcua/secevent"
	"github.com/gopcua/opcua/ua"
)

type recorder struct {
	mu     sync.Mutex
	events []secevent.Event
	ch     chan secevent.Event
}

func newRecorder() *recorder { return &recorder{ch: make(chan secevent.Event, 100)} }

func (r *recorder) handle(e secevent.Event) {
	r.mu.Lock()
	r.events = append(r.events, e)
	r.mu.Unlock()
	select {
	case r.ch <- e:
	default:
	}
}

// wait returns the first event of kind k, or fails after a timeout.
func (r *recorder) wait(t *testing.T, k secevent.Kind) secevent.Event {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case e := <-r.ch:
			if e.Kind == k {
				return e
			}
		case <-deadline:
			r.mu.Lock()
			defer r.mu.Unlock()
			var ks []secevent.Kind
			for _, e := range r.events {
				ks = append(ks, e.Kind)
			}
			t.Fatalf("no %s event, got %v", k, ks)
			return secevent.Event{}
		}
	}
}

func listen(t *testing.T, opts ...ListenOption) *Listener {
	t.Helper()
	ln, err := Listen(context.Background(), "opc.tcp://127.0.0.1:0", nil, opts...)
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })
	return ln
}

func endpointOf(ln *Listener) string { return "opc.tcp://" + ln.Addr().String() }

// acceptAsync runs Accept until the listener closes and passes the
// connections on.
func acceptAsync(t *testing.T, ln *Listener) <-chan *Conn {
	ch := make(chan *Conn, 10)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() {
		for {
			c, err := ln.Accept(ctx)
			if err != nil {
				return
			}
			t.Cleanup(func() { c.Close() })
			ch <- c
		}
	}()
	return ch
}

// A peer that connects and never sends Hello is disconnected after the
// handshake timeout and reported; it does not hold up a well-behaved
// client, and Accept does not return an error for it.
func TestSilentPeerDoesNotBlockAccept(t *testing.T) {
	rec := newRecorder()
	ln := listen(t, WithEventHandler(rec.handle), WithHandshakeTimeout(200*time.Millisecond))
	conns := acceptAsync(t, ln)

	silent, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	defer silent.Close()
	rec.wait(t, secevent.ConnectionAccepted)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c, err := Dial(ctx, endpointOf(ln))
	require.NoError(t, err, "a silent peer must not block the handshake of another")
	defer c.Close()

	select {
	case <-conns:
	case <-time.After(2 * time.Second):
		t.Fatal("well-behaved client not accepted")
	}

	e := rec.wait(t, secevent.HandshakeFailed)
	require.Contains(t, e.Detail, "no handshake within")

	// the silent peer has been disconnected
	_ = silent.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = silent.Read(make([]byte, 64))
	require.Error(t, err)
}

// A peer that connects and closes (a port scan) is reported and Accept
// carries on.
func TestPortScanIsReported(t *testing.T) {
	rec := newRecorder()
	ln := listen(t, WithEventHandler(rec.handle))
	conns := acceptAsync(t, ln)

	scan, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	scan.Close()

	e := rec.wait(t, secevent.HandshakeFailed)
	require.Contains(t, e.Detail, "closed before the handshake")

	c, err := Dial(context.Background(), endpointOf(ln))
	require.NoError(t, err)
	defer c.Close()
	<-conns
}

func TestAllowedPeers(t *testing.T) {
	rec := newRecorder()
	ln := listen(t, WithEventHandler(rec.handle), WithAllowedPeers(netip.MustParsePrefix("192.0.2.0/24")))
	acceptAsync(t, ln)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := Dial(ctx, endpointOf(ln))
	require.Error(t, err)

	e := rec.wait(t, secevent.ConnectionRejected)
	require.Equal(t, "127.0.0.1", e.Remote.(*net.TCPAddr).IP.String())
}

func TestMaxConnectionsPerIP(t *testing.T) {
	rec := newRecorder()
	ln := listen(t, WithEventHandler(rec.handle), WithMaxConnections(0, 1))
	conns := acceptAsync(t, ln)

	ctx := context.Background()
	c1, err := Dial(ctx, endpointOf(ln))
	require.NoError(t, err)
	srv1 := <-conns

	_, err = Dial(ctx, endpointOf(ln))
	require.ErrorIs(t, err, ua.StatusBadTCPServerTooBusy)
	e := rec.wait(t, secevent.ConnectionLimit)
	require.Equal(t, ua.StatusBadTCPServerTooBusy, e.Status)

	// closing the first connection frees its slot
	c1.Close()
	srv1.Close()
	c3, err := Dial(ctx, endpointOf(ln))
	require.NoError(t, err)
	c3.Close()
}

func TestConnectionFloodIsReportedOnce(t *testing.T) {
	rec := newRecorder()
	ln := listen(t, WithEventHandler(rec.handle), WithConnectionRateLimit(secevent.RateLimit{Max: 2, Window: time.Minute}))
	acceptAsync(t, ln)

	for i := 0; i < 5; i++ {
		c, err := Dial(context.Background(), endpointOf(ln))
		require.NoError(t, err, "not enforced")
		c.Close()
	}
	rec.wait(t, secevent.ConnectionFlood)

	rec.mu.Lock()
	defer rec.mu.Unlock()
	n := 0
	for _, e := range rec.events {
		if e.Kind == secevent.ConnectionFlood {
			n++
		}
	}
	require.Equal(t, 1, n)
}

func TestConnectionFloodEnforced(t *testing.T) {
	ln := listen(t, WithConnectionRateLimit(secevent.RateLimit{Max: 1, Window: time.Minute, Enforce: true}))
	acceptAsync(t, ln)

	c, err := Dial(context.Background(), endpointOf(ln))
	require.NoError(t, err)
	c.Close()
	_, err = Dial(context.Background(), endpointOf(ln))
	require.ErrorIs(t, err, ua.StatusBadTCPServerTooBusy)
}

// rawHello writes a frame with the given header and body to a raw
// connection.
func rawFrame(typ string, chunk byte, size uint32, body []byte) []byte {
	b := make([]byte, 8, 8+len(body))
	copy(b, typ)
	b[3] = chunk
	binary.LittleEndian.PutUint32(b[4:], size)
	return append(b, body...)
}

func TestInvalidMessageTypeIsReported(t *testing.T) {
	rec := newRecorder()
	ln := listen(t, WithEventHandler(rec.handle))
	acceptAsync(t, ln)

	c, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	defer c.Close()
	_, err = c.Write(rawFrame("XYZ", 'F', 8, nil))
	require.NoError(t, err)

	e := rec.wait(t, secevent.MalformedMessage)
	require.Equal(t, ua.StatusBadTCPMessageTypeInvalid, e.Status)
	rec.wait(t, secevent.HandshakeFailed)
}

func TestOversizedHelloIsReported(t *testing.T) {
	rec := newRecorder()
	ln := listen(t, WithEventHandler(rec.handle))
	acceptAsync(t, ln)

	c, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	defer c.Close()
	_, err = c.Write(rawFrame("HEL", 'F', 1<<30, nil))
	require.NoError(t, err)

	e := rec.wait(t, secevent.OversizedMessage)
	require.Equal(t, ua.StatusBadTCPMessageTooLarge, e.Status)
}

func TestTooLongEndpointURLIsRejected(t *testing.T) {
	rec := newRecorder()
	ln := listen(t, WithEventHandler(rec.handle))
	acceptAsync(t, ln)

	long := "opc.tcp://" + string(make([]byte, maxEndpointURLLength))
	c, err := NewConn(mustDial(t, ln), nil)
	require.NoError(t, err)
	defer c.Close()
	err = c.Handshake(context.Background(), long)
	require.ErrorIs(t, err, ua.StatusBadTCPEndpointURLInvalid)
	rec.wait(t, secevent.MalformedMessage)
}

func mustDial(t *testing.T, ln *Listener) *net.TCPConn {
	t.Helper()
	c, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	return c.(*net.TCPConn)
}

func TestPendingHandshakeLimit(t *testing.T) {
	rec := newRecorder()
	ln := listen(t, WithEventHandler(rec.handle), WithMaxPendingHandshakes(1), WithHandshakeTimeout(5*time.Second))
	acceptAsync(t, ln)

	silent := mustDial(t, ln)
	defer silent.Close()
	rec.wait(t, secevent.ConnectionAccepted)

	_, err := Dial(context.Background(), endpointOf(ln))
	require.ErrorIs(t, err, ua.StatusBadTCPServerTooBusy)
	rec.wait(t, secevent.ConnectionLimit)
}

// Events of an accepted connection carry its addresses and id.
func TestConnEmitFillsConnectionDetails(t *testing.T) {
	rec := newRecorder()
	ln := listen(t, WithEventHandler(rec.handle))
	conns := acceptAsync(t, ln)

	c, err := Dial(context.Background(), endpointOf(ln))
	require.NoError(t, err)
	defer c.Close()
	srv := <-conns

	srv.Emit(secevent.Event{Kind: secevent.MalformedMessage})
	e := rec.wait(t, secevent.MalformedMessage)
	require.Equal(t, srv.ID(), e.ConnID)
	require.Equal(t, c.LocalAddr().String(), e.Remote.String())
	require.NotNil(t, e.Local)

	_, err = srv.RemoteMAC()
	require.ErrorIs(t, err, secevent.ErrMACUnavailable, "loopback has no MAC")
}

func TestDialerEvents(t *testing.T) {
	rec := newRecorder()
	ln := listen(t)
	acceptAsync(t, ln)
	d := &Dialer{Events: rec.handle, MACs: secevent.NewMACTracker()}
	c, err := d.Dial(context.Background(), endpointOf(ln))
	require.NoError(t, err)
	defer c.Close()
	require.NotNil(t, c.EventHandler())
}

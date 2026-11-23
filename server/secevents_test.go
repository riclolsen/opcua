// Copyright 2018-2026 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package server_test

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/gopcua/opcua"
	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/secevent"
	"github.com/gopcua/opcua/server"
	"github.com/gopcua/opcua/ua"
)

type recorder struct {
	mu     sync.Mutex
	events []secevent.Event
}

func (r *recorder) handle(e secevent.Event) {
	r.mu.Lock()
	r.events = append(r.events, e)
	r.mu.Unlock()
}

func (r *recorder) all(k secevent.Kind) []secevent.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []secevent.Event
	for _, e := range r.events {
		if e.Kind == k {
			out = append(out, e)
		}
	}
	return out
}

// wait returns the events of kind k once there is at least one.
func (r *recorder) wait(t *testing.T, k secevent.Kind) []secevent.Event {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if es := r.all(k); len(es) > 0 {
			return es
		}
		time.Sleep(10 * time.Millisecond)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	var ks []secevent.Kind
	for _, e := range r.events {
		ks = append(ks, e.Kind)
	}
	t.Fatalf("no %s event, got %v", k, ks)
	return nil
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

type fixture struct {
	srv    *server.Server
	ns     *server.NodeNameSpace
	client *opcua.Client
	rec    *recorder
	crec   *recorder
}

func start(t *testing.T, opts ...server.Option) *fixture {
	t.Helper()
	rec, crec := &recorder{}, &recorder{}
	port := freePort(t)
	opts = append([]server.Option{
		server.EnableSecurity("None", ua.MessageSecurityModeNone),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
		server.EndPoint("127.0.0.1", port),
		server.SecurityEventHandler(rec.handle),
	}, opts...)
	srv := server.New(opts...)
	ns := server.NewNodeNameSpace(srv, "test")

	n := ns.AddNewVariableStringNode("int32", int32(1))
	n.SetAttribute(ua.AttributeIDDataType, server.DataValueFromValue(ua.NewNumericNodeID(0, id.Int32)))
	n.SetAttribute(ua.AttributeIDAccessLevel, server.DataValueFromValue(byte(ua.AccessLevelTypeCurrentRead|ua.AccessLevelTypeCurrentWrite)))
	ro := ns.AddNewVariableStringNode("readonly", int32(1))
	ro.SetAttribute(ua.AttributeIDAccessLevel, server.DataValueFromValue(byte(ua.AccessLevelTypeCurrentRead)))

	ctx := context.Background()
	require.NoError(t, srv.Start(ctx))
	t.Cleanup(func() { srv.Close() })

	c, err := opcua.NewClient("opc.tcp://127.0.0.1:"+itoa(port),
		opcua.SecurityMode(ua.MessageSecurityModeNone),
		opcua.SecurityEventHandler(crec.handle),
		opcua.AutoReconnect(false),
	)
	require.NoError(t, err)
	require.NoError(t, c.Connect(ctx))
	t.Cleanup(func() { c.Close(context.Background()) })

	return &fixture{srv: srv, ns: ns, client: c, rec: rec, crec: crec}
}

func itoa(n int) string { return (&net.TCPAddr{Port: n}).String()[1:] }

func (f *fixture) nid(name string) *ua.NodeID { return ua.NewStringNodeID(f.ns.ID(), name) }

func TestEventsForEveryConnection(t *testing.T) {
	f := start(t)
	es := f.rec.wait(t, secevent.ConnectionAccepted)
	require.Equal(t, secevent.Info, es[0].Severity)
	require.Equal(t, "127.0.0.1", es[0].Remote.(*net.TCPAddr).IP.String())
}

func TestReadOfUnknownNodes(t *testing.T) {
	f := start(t)
	ctx := context.Background()
	resp, err := f.client.Read(ctx, &ua.ReadRequest{NodesToRead: []*ua.ReadValueID{
		{NodeID: f.nid("int32"), AttributeID: ua.AttributeIDValue},
		{NodeID: f.nid("missing"), AttributeID: ua.AttributeIDValue},
		{NodeID: ua.NewNumericNodeID(77, 1), AttributeID: ua.AttributeIDValue},
	}})
	require.NoError(t, err)
	require.Len(t, resp.Results, 3)

	es := f.rec.wait(t, secevent.UnknownNode)
	require.Len(t, es, 2)
	var got []string
	for _, e := range es {
		require.Equal(t, "ReadRequest", e.Service)
		require.NotZero(t, e.SecureChannelID, "events carry the channel")
		require.NotZero(t, e.ConnID)
		got = append(got, e.NodeID.String())
	}
	require.ElementsMatch(t, []string{f.nid("missing").String(), "ns=77;i=1"}, got)
}

func TestAddressScanIsDetected(t *testing.T) {
	f := start(t, server.AddressScanLimit(secevent.RateLimit{Max: 5, Window: time.Minute}))
	var nodes []*ua.ReadValueID
	for i := 0; i < 10; i++ {
		nodes = append(nodes, &ua.ReadValueID{NodeID: ua.NewNumericNodeID(f.ns.ID(), uint32(1000+i)), AttributeID: ua.AttributeIDValue})
	}
	_, err := f.client.Read(context.Background(), &ua.ReadRequest{NodesToRead: nodes})
	require.NoError(t, err)
	es := f.rec.wait(t, secevent.AddressScan)
	require.Len(t, es, 1)
	require.Equal(t, secevent.Alert, es[0].Severity)
}

func TestOversizedRead(t *testing.T) {
	f := start(t, server.MaxNodesPerRead(2))
	var nodes []*ua.ReadValueID
	for i := 0; i < 3; i++ {
		nodes = append(nodes, &ua.ReadValueID{NodeID: f.nid("int32"), AttributeID: ua.AttributeIDValue})
	}
	_, err := f.client.Read(context.Background(), &ua.ReadRequest{NodesToRead: nodes})
	require.ErrorIs(t, err, ua.StatusBadTooManyOperations)
	es := f.rec.wait(t, secevent.OversizedRequest)
	require.Equal(t, ua.StatusBadTooManyOperations, es[0].Status)
	require.Empty(t, f.rec.all(secevent.RequestRejected), "reported once, as oversized")
}

func TestWrites(t *testing.T) {
	f := start(t)
	ctx := context.Background()
	resp, err := f.client.Write(ctx, &ua.WriteRequest{NodesToWrite: []*ua.WriteValue{
		{NodeID: f.nid("int32"), AttributeID: ua.AttributeIDValue, Value: &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(int32(7))}},
		{NodeID: f.nid("int32"), AttributeID: ua.AttributeIDValue, Value: &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant("seven")}},
		{NodeID: f.nid("readonly"), AttributeID: ua.AttributeIDValue, Value: &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(int32(7))}},
		{NodeID: f.nid("missing"), AttributeID: ua.AttributeIDValue, Value: &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(int32(7))}},
	}})
	require.NoError(t, err)
	require.Equal(t, []ua.StatusCode{ua.StatusOK, ua.StatusBadTypeMismatch, ua.StatusBadUserAccessDenied, ua.StatusBadNodeIDUnknown}, resp.Results)

	pc := f.rec.wait(t, secevent.ParameterChange)
	require.Len(t, pc, 1)
	require.Equal(t, secevent.Notice, pc[0].Severity)
	require.Equal(t, f.nid("int32").String(), pc[0].NodeID.String())
	require.Len(t, f.rec.wait(t, secevent.TypeMismatch), 1)
	require.Len(t, f.rec.wait(t, secevent.AccessDenied), 1)
	require.Len(t, f.rec.wait(t, secevent.UnknownNode), 1)
}

func TestMethodCalls(t *testing.T) {
	f := start(t)
	ctx := context.Background()
	_, err := f.client.Call(ctx, &ua.CallMethodRequest{
		ObjectID: ua.NewNumericNodeID(0, id.Server),
		MethodID: ua.NewNumericNodeID(0, id.Server_RequestServerStateChange),
	})
	require.Error(t, err, "the server does not implement Call")
	_, _ = f.client.Call(ctx, &ua.CallMethodRequest{
		ObjectID: ua.NewNumericNodeID(0, id.Server),
		MethodID: f.nid("no-such-method"),
	})

	calls := f.rec.wait(t, secevent.MethodCall)
	require.Len(t, calls, 2)
	require.Equal(t, secevent.Alert, calls[0].Severity, "server state change")
	require.Contains(t, calls[0].Detail, "server state change")
	require.Equal(t, secevent.Notice, calls[1].Severity)

	unknown := f.rec.wait(t, secevent.UnknownCommand)
	var methods, services int
	for _, e := range unknown {
		if e.Status == ua.StatusBadMethodInvalid {
			methods++
		}
		if e.Status == ua.StatusBadServiceUnsupported {
			services++
		}
	}
	require.Equal(t, 1, methods, "unknown method")
	require.Equal(t, 2, services, "Call is not supported")
}

func TestRequestFloodEnforced(t *testing.T) {
	f := start(t, server.RequestRateLimit(secevent.RateLimit{Max: 3, Window: time.Minute, Enforce: true}))
	ctx := context.Background()
	var err error
	for i := 0; i < 5 && err == nil; i++ {
		_, err = f.client.Read(ctx, &ua.ReadRequest{NodesToRead: []*ua.ReadValueID{{NodeID: f.nid("int32"), AttributeID: ua.AttributeIDValue}}})
	}
	require.ErrorIs(t, err, ua.StatusBadTooManyOperations)
	require.Len(t, f.rec.wait(t, secevent.RequestFlood), 1)
}

func TestSessionLimit(t *testing.T) {
	f := start(t, server.MaxSessions(1))
	c2, err := opcua.NewClient(f.srv.URLs()[0], opcua.SecurityMode(ua.MessageSecurityModeNone), opcua.AutoReconnect(false))
	require.NoError(t, err)
	err = c2.Connect(context.Background())
	require.ErrorIs(t, err, ua.StatusBadTooManySessions)
	c2.Close(context.Background())
	require.Len(t, f.rec.wait(t, secevent.SessionLimit), 1)
}

func TestUnsupportedServiceAndUnknownSession(t *testing.T) {
	f := start(t)
	ctx := context.Background()
	_, err := f.client.HistoryReadRawModified(ctx, []*ua.HistoryReadValueID{{NodeID: f.nid("int32")}}, &ua.ReadRawModifiedDetails{})
	require.Error(t, err)
	es := f.rec.wait(t, secevent.UnknownCommand)
	require.Equal(t, "HistoryReadRequest", es[0].Service)

	// A request outside the session.
	req := &ua.ReadRequest{NodesToRead: []*ua.ReadValueID{{NodeID: f.nid("int32"), AttributeID: ua.AttributeIDValue}}}
	err = f.client.SecureChannel().SendRequest(ctx, req, ua.NewNumericNodeID(0, 4242), func(ua.Response) error { return nil })
	require.NoError(t, err)
	f.rec.wait(t, secevent.UnknownSession)
}

func TestClientMAC(t *testing.T) {
	f := start(t)
	_, err := f.client.RemoteMAC()
	require.ErrorIs(t, err, secevent.ErrMACUnavailable, "loopback has no MAC")
}

// A client that resets its connection in the middle of the Hello used to end
// the server's accept loop: the reset surfaced from Accept as a
// *net.OpError, which the loop took for a closed listener. Every later
// client was refused.
func TestResetDuringHandshakeKeepsServing(t *testing.T) {
	f := start(t)
	addr := f.srv.URLs()[0][len("opc.tcp://"):]

	c, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	_, err = c.Write([]byte("HEL"))
	require.NoError(t, err)
	time.Sleep(100 * time.Millisecond)
	require.NoError(t, c.(*net.TCPConn).SetLinger(0))
	require.NoError(t, c.Close())
	f.rec.wait(t, secevent.HandshakeFailed)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c2, err := opcua.NewClient(f.srv.URLs()[0], opcua.SecurityMode(ua.MessageSecurityModeNone), opcua.AutoReconnect(false))
	require.NoError(t, err)
	require.NoError(t, c2.Connect(ctx), "server must keep accepting after a reset")
	c2.Close(ctx)
}

// The server closes the connection of a channel that ended, so that the
// listener's connection limits get their slot back: with a limit of one,
// a client can reconnect again and again.
func TestConnectionSlotIsReleasedOnDisconnect(t *testing.T) {
	f := start(t, server.MaxConnections(1, 1))
	ctx := context.Background()
	require.NoError(t, f.client.Close(ctx))

	for i := 0; i < 3; i++ {
		var c *opcua.Client
		var err error
		// The server notices the previous disconnect asynchronously.
		require.Eventually(t, func() bool {
			c, err = opcua.NewClient(f.srv.URLs()[0], opcua.SecurityMode(ua.MessageSecurityModeNone), opcua.AutoReconnect(false))
			require.NoError(t, err)
			cctx, cancel := context.WithTimeout(ctx, time.Second)
			defer cancel()
			if c.Connect(cctx) != nil {
				c.Close(ctx)
				return false
			}
			return true
		}, 5*time.Second, 50*time.Millisecond, "reconnect %d", i)
		require.NoError(t, c.Close(ctx))
	}
}

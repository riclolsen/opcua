// Copyright 2018-2026 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package secevent

import (
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/gopcua/opcua/ua"
)

func TestCounterReportsOncePerWindow(t *testing.T) {
	c := NewCounter(RateLimit{Max: 3, Window: time.Second})
	now := time.Unix(1000, 0)

	for i := 0; i < 3; i++ {
		ex, _ := c.Hit("a", now)
		require.False(t, ex, "hit %d", i)
	}
	ex, first := c.Hit("a", now)
	require.True(t, ex)
	require.True(t, first)
	ex, first = c.Hit("a", now)
	require.True(t, ex)
	require.False(t, first, "a flood is reported once per window")

	// other keys are counted apart
	ex, _ = c.Hit("b", now)
	require.False(t, ex)

	// a new window starts afresh
	ex, _ = c.Hit("a", now.Add(time.Second))
	require.False(t, ex)
}

func TestCounterDisabledAndNil(t *testing.T) {
	var c *Counter
	ex, _ := c.Hit("a", time.Now())
	require.False(t, ex)
	ex, _ = NewCounter(RateLimit{}).Hit("a", time.Now())
	require.False(t, ex)
}

// An attacker choosing many keys must not grow the counter without bound.
func TestCounterIsBounded(t *testing.T) {
	c := NewCounter(RateLimit{Max: 1, Window: time.Hour})
	now := time.Now()
	for i := 0; i < maxKeys*2; i++ {
		c.Hit(strings.Repeat("x", 1)+string(rune(i)), now)
	}
	require.LessOrEqual(t, len(c.buckets), maxKeys+1)
}

func TestMACTracker(t *testing.T) {
	tr := NewMACTracker()
	ip := net.ParseIP("192.0.2.1")
	mac1 := net.HardwareAddr{0, 1, 2, 3, 4, 5}
	mac2 := net.HardwareAddr{0, 1, 2, 3, 4, 6}

	_, changed := tr.Observe(ip, mac1)
	require.False(t, changed, "first sighting")
	_, changed = tr.Observe(ip, mac1)
	require.False(t, changed, "same MAC")
	prev, changed := tr.Observe(ip, mac2)
	require.True(t, changed)
	require.Equal(t, mac1, prev)

	// an IPv4-mapped IPv6 address is the same peer
	_, changed = tr.Observe(net.ParseIP("::ffff:192.0.2.1"), mac2)
	require.False(t, changed)

	// an unknown MAC is ignored
	_, changed = tr.Observe(ip, nil)
	require.False(t, changed)
}

func TestLookupMACLoopbackIsUnavailable(t *testing.T) {
	_, err := LookupMAC(net.ParseIP("127.0.0.1"))
	require.ErrorIs(t, err, ErrMACUnavailable)
	_, err = LookupAddrMAC(&net.TCPAddr{IP: net.ParseIP("::1"), Port: 1})
	require.ErrorIs(t, err, ErrMACUnavailable)
	_, err = LookupAddrMAC(&net.UnixAddr{})
	require.ErrorIs(t, err, ErrMACUnavailable)
}

func TestEmitRecoversAndStamps(t *testing.T) {
	var got Event
	Handler(func(e Event) { got = e }).Emit(Event{Kind: MalformedMessage})
	require.False(t, got.Time.IsZero())

	require.NotPanics(t, func() {
		Handler(func(Event) { panic("boom") }).Emit(Event{})
	})
	require.NotPanics(t, func() { Handler(nil).Emit(Event{}) })
}

func TestAsyncDropsWhenFull(t *testing.T) {
	block := make(chan struct{})
	var n atomic.Int32
	a := Async(func(Event) { <-block; n.Add(1) }, 1)
	for i := 0; i < 10; i++ {
		a.Handle(Event{})
	}
	require.NotZero(t, a.Dropped())
	close(block)
	a.Close()
	require.Equal(t, uint64(10), uint64(n.Load())+a.Dropped())
}

func TestEventString(t *testing.T) {
	e := Event{
		Kind:      UnknownNode,
		Severity:  Warning,
		Remote:    &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 4840},
		RemoteMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5},
		Service:   "ReadRequest",
		NodeID:    ua.NewNumericNodeID(2, 7),
		Status:    ua.StatusBadNodeIDUnknown,
	}
	s := e.String()
	for _, want := range []string{"warning", "service.unknown_node", "192.0.2.1:4840", "00:01:02:03:04:05", "ReadRequest", "ns=2;i=7", "StatusBadNodeIDUnknown"} {
		require.Contains(t, s, want)
	}
}

func TestServiceName(t *testing.T) {
	require.Equal(t, "ReadRequest", ServiceName(&ua.ReadRequest{}))
	require.Equal(t, "", ServiceName(nil))
}

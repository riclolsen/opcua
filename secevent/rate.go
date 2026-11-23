// Copyright 2018-2026 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package secevent

import (
	"bytes"
	"net"
	"net/netip"
	"sync"
	"time"
)

// RateLimit is a limit of Max events per Window.
//
// A limit with Max <= 0 or Window <= 0 is disabled. When Enforce is false
// exceeding the limit is only reported; when it is true the operation that
// exceeds it is also refused.
type RateLimit struct {
	Max     int
	Window  time.Duration
	Enforce bool
}

// Enabled reports whether the limit is active.
func (l RateLimit) Enabled() bool { return l.Max > 0 && l.Window > 0 }

// maxKeys bounds the memory of a Counter and a MACTracker: an attacker who
// can choose many source addresses must not be able to grow them without
// bound.
const maxKeys = 16384

// Counter counts events per key in fixed windows. It is safe for concurrent
// use.
type Counter struct {
	limit RateLimit

	mu        sync.Mutex
	buckets   map[string]*bucket
	lastSweep time.Time
}

type bucket struct {
	start    time.Time
	n        int
	reported bool
}

// NewCounter returns a counter for limit.
func NewCounter(limit RateLimit) *Counter {
	return &Counter{limit: limit, buckets: make(map[string]*bucket)}
}

// Limit returns the limit of the counter.
func (c *Counter) Limit() RateLimit {
	if c == nil {
		return RateLimit{}
	}
	return c.limit
}

// Hit counts one event for key at now. It returns whether the event exceeds
// the limit, and whether this is the first event in the current window that
// exceeds it, so that a caller reports a flood once per window instead of
// once per event. A nil or disabled counter never exceeds.
func (c *Counter) Hit(key string, now time.Time) (exceeded, first bool) {
	if c == nil || !c.limit.Enabled() {
		return false, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	// Drop expired buckets once per window, and sooner when the map is
	// full, but never on every hit: a sweep is linear in the map size.
	if since := now.Sub(c.lastSweep); since >= c.limit.Window || len(c.buckets) >= maxKeys && since >= c.limit.Window/8 {
		c.sweep(now)
	}

	b := c.buckets[key]
	if b == nil || now.Sub(b.start) >= c.limit.Window {
		if b == nil && len(c.buckets) >= maxKeys {
			// Every bucket is live: share one overflow bucket so that
			// counting continues without growing the map.
			key = "\x00overflow"
			b = c.buckets[key]
		}
		if b == nil || now.Sub(b.start) >= c.limit.Window {
			b = &bucket{start: now}
			c.buckets[key] = b
		}
	}
	b.n++
	if b.n <= c.limit.Max {
		return false, false
	}
	first = !b.reported
	b.reported = true
	return true, first
}

// Forget drops the count of key.
func (c *Counter) Forget(key string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	delete(c.buckets, key)
	c.mu.Unlock()
}

func (c *Counter) sweep(now time.Time) {
	c.lastSweep = now
	for k, b := range c.buckets {
		if now.Sub(b.start) >= c.limit.Window {
			delete(c.buckets, k)
		}
	}
}

// MACTracker remembers the MAC address last seen for an IP address and
// reports when it changes. It is safe for concurrent use.
type MACTracker struct {
	mu sync.Mutex
	m  map[netip.Addr]net.HardwareAddr
}

// NewMACTracker returns an empty tracker.
func NewMACTracker() *MACTracker {
	return &MACTracker{m: make(map[netip.Addr]net.HardwareAddr)}
}

// Observe records mac for ip. If a different MAC address was recorded for
// ip before, it returns that address and true. An empty mac is ignored.
func (t *MACTracker) Observe(ip net.IP, mac net.HardwareAddr) (previous net.HardwareAddr, changed bool) {
	if t == nil || len(mac) == 0 {
		return nil, false
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return nil, false
	}
	addr = addr.Unmap()

	t.mu.Lock()
	defer t.mu.Unlock()
	old, seen := t.m[addr]
	if seen && bytes.Equal(old, mac) {
		return nil, false
	}
	if !seen && len(t.m) >= maxKeys {
		for k := range t.m {
			delete(t.m, k)
			break
		}
	}
	t.m[addr] = append(net.HardwareAddr(nil), mac...)
	if seen {
		return old, true
	}
	return nil, false
}

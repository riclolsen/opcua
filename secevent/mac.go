// Copyright 2018-2026 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package secevent

import (
	"errors"
	"net"
)

// ErrMACUnavailable is returned by LookupMAC when the MAC address of a peer
// cannot be determined: the peer is not on a directly attached network (its
// packets arrive through a router, whose MAC address says nothing about the
// peer), it is the local host, the neighbor table has no entry for it, or
// the platform is not supported.
var ErrMACUnavailable = errors.New("secevent: MAC address unavailable")

// LookupMAC returns the MAC address of the neighbor with the given IP
// address from the operating system's neighbor table (ARP for IPv4, NDP for
// IPv6). It is supported on Linux; on other platforms it returns
// ErrMACUnavailable.
//
// The neighbor table holds an entry for a peer that recently exchanged
// packets with this host, so the lookup succeeds right after a TCP
// connection with a peer on the same link has been established.
func LookupMAC(ip net.IP) (net.HardwareAddr, error) {
	if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
		return nil, ErrMACUnavailable
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	return lookupMAC(ip)
}

// LookupAddrMAC is LookupMAC for a net.Addr of a TCP or UDP connection.
func LookupAddrMAC(addr net.Addr) (net.HardwareAddr, error) {
	switch a := addr.(type) {
	case *net.TCPAddr:
		return LookupMAC(a.IP)
	case *net.UDPAddr:
		return LookupMAC(a.IP)
	case *net.IPAddr:
		return LookupMAC(a.IP)
	}
	return nil, ErrMACUnavailable
}

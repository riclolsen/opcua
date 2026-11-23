// Copyright 2018-2026 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

//go:build linux

package secevent

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"net"
	"os"
	"strings"
	"syscall"
)

// Neighbor table constants from linux/neighbour.h.
const (
	ndaDst    = 1
	ndaLLAddr = 2

	nudIncomplete = 0x01
	nudFailed     = 0x20
	nudNoARP      = 0x40

	sizeofNdMsg = 12
)

func lookupMAC(ip net.IP) (net.HardwareAddr, error) {
	family := syscall.AF_INET6
	if len(ip) == net.IPv4len {
		family = syscall.AF_INET
	}
	if mac, err := lookupNetlink(ip, family); err == nil {
		return mac, nil
	}
	if family == syscall.AF_INET {
		return lookupProcARP(ip)
	}
	return nil, ErrMACUnavailable
}

// lookupNetlink dumps the neighbor table through rtnetlink.
func lookupNetlink(ip net.IP, family int) (net.HardwareAddr, error) {
	tab, err := syscall.NetlinkRIB(syscall.RTM_GETNEIGH, family)
	if err != nil {
		return nil, err
	}
	msgs, err := syscall.ParseNetlinkMessage(tab)
	if err != nil {
		return nil, err
	}
	for _, m := range msgs {
		if m.Header.Type != syscall.RTM_NEWNEIGH || len(m.Data) < sizeofNdMsg {
			continue
		}
		state := binary.NativeEndian.Uint16(m.Data[8:10])
		if state&(nudIncomplete|nudFailed|nudNoARP) != 0 {
			continue
		}
		var dst, lladdr []byte
		for b := m.Data[sizeofNdMsg:]; len(b) >= 4; {
			l := int(binary.NativeEndian.Uint16(b[0:2]))
			typ := binary.NativeEndian.Uint16(b[2:4])
			if l < 4 || l > len(b) {
				break
			}
			switch typ {
			case ndaDst:
				dst = b[4:l]
			case ndaLLAddr:
				lladdr = b[4:l]
			}
			al := (l + 3) &^ 3
			if al > len(b) {
				break
			}
			b = b[al:]
		}
		if bytes.Equal(dst, ip) && validMAC(lladdr) {
			return append(net.HardwareAddr(nil), lladdr...), nil
		}
	}
	return nil, ErrMACUnavailable
}

// lookupProcARP reads the IPv4 neighbor table from /proc/net/arp, for
// environments where rtnetlink is not available.
func lookupProcARP(ip net.IP) (net.HardwareAddr, error) {
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return nil, ErrMACUnavailable
	}
	defer f.Close()
	want := ip.String()
	sc := bufio.NewScanner(f)
	sc.Scan() // header
	for sc.Scan() {
		// IP address  HW type  Flags  HW address  Mask  Device
		fs := strings.Fields(sc.Text())
		if len(fs) < 4 || fs[0] != want || fs[2] == "0x0" {
			continue
		}
		mac, err := net.ParseMAC(fs[3])
		if err == nil && validMAC(mac) {
			return mac, nil
		}
	}
	return nil, ErrMACUnavailable
}

func validMAC(mac []byte) bool {
	if len(mac) == 0 {
		return false
	}
	for _, b := range mac {
		if b != 0 {
			return true
		}
	}
	return false
}

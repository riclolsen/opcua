// Copyright 2018-2026 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

//go:build !linux

package secevent

import "net"

func lookupMAC(net.IP) (net.HardwareAddr, error) { return nil, ErrMACUnavailable }

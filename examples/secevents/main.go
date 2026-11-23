// Copyright 2018-2026 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

// Example secevents runs a server that logs the security events it detects
// as structured log lines, e.g. for a SIEM.
//
// Try it with any client, or provoke events by hand:
//
//	nc localhost 4840                          # connection.accepted, then connection.handshake_failed after 5s
//	go run ./examples/read -node 'ns=1;s=nope' # service.unknown_node
package main

import (
	"context"
	"flag"
	"log"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"time"

	"github.com/gopcua/opcua/secevent"
	"github.com/gopcua/opcua/server"
	"github.com/gopcua/opcua/ua"
)

func main() {
	host := flag.String("host", "localhost", "host to listen on")
	port := flag.Int("port", 4840, "port to listen on")
	allow := flag.String("allow", "", "only accept clients from this network, e.g. 192.168.0.0/24")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	// Decouple logging from the protocol goroutines: the handler is called
	// synchronously, and an attacker controls the rate of most events.
	async := secevent.Async(func(e secevent.Event) {
		attrs := []any{
			"kind", e.Kind,
			"severity", e.Severity.String(),
			"remote", addr(e.Remote),
			"mac", e.RemoteMAC.String(),
			"conn", e.ConnID,
			"channel", e.SecureChannelID,
		}
		if e.Service != "" {
			attrs = append(attrs, "service", e.Service)
		}
		if e.NodeID != nil {
			attrs = append(attrs, "node", e.NodeID.String())
		}
		if e.Status != 0 {
			attrs = append(attrs, "status", e.Status.Error())
		}
		if e.Detail != "" {
			attrs = append(attrs, "detail", e.Detail)
		}
		if len(e.PreviousMAC) > 0 {
			attrs = append(attrs, "previous_mac", e.PreviousMAC.String())
		}
		level := slog.LevelInfo
		switch e.Severity {
		case secevent.Warning:
			level = slog.LevelWarn
		case secevent.Alert:
			level = slog.LevelError
		}
		logger.Log(context.Background(), level, "security event", attrs...)
	}, 4096)
	defer async.Close()

	opts := []server.Option{
		server.EnableSecurity("None", ua.MessageSecurityModeNone),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
		server.EndPoint(*host, *port),
		server.SecurityEventHandler(async.Handle),
		server.HandshakeTimeout(5 * time.Second),
		server.MaxConnections(100, 10),
		server.MaxSessions(100),
		server.ConnectionRateLimit(secevent.RateLimit{Max: 20, Window: 10 * time.Second, Enforce: true}),
		server.RequestRateLimit(secevent.RateLimit{Max: 500, Window: time.Second, Enforce: true}),
	}
	if *allow != "" {
		opts = append(opts, server.AllowedPeers(netip.MustParsePrefix(*allow)))
	}

	srv := server.New(opts...)
	ns := server.NewNodeNameSpace(srv, "example")
	ns.AddNewVariableStringNode("value", int32(42))

	if err := srv.Start(context.Background()); err != nil {
		log.Fatal(err)
	}
	defer srv.Close()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	<-sig
}

func addr(a interface{ String() string }) string {
	if a == nil {
		return ""
	}
	return a.String()
}

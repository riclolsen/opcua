// Copyright 2018-2026 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

// Package secevent reports security relevant protocol events.
//
// The OPC UA stack reports events that an intrusion detection system, a SIEM
// or an operator would want to know about: connections to the listener,
// rejected certificates, malformed messages, replayed or out of order
// sequence numbers, reads of unknown nodes, unsupported services, writes and
// method calls that change the state of the server, floods and connection
// exhaustion, and a change of the MAC address behind a peer's IP address.
//
// Events are delivered to a Handler. A Handler is called synchronously on the
// goroutine that detected the event, so it must return quickly and must not
// call back into the connection that reported it. Wrap a slow handler with
// Async to decouple it from the protocol goroutines.
//
// The server takes a handler with server.SecurityEventHandler and the client
// with opcua.SecurityEventHandler. Lower layers take it with
// uacp.WithEventHandler for a listener and uacp.Dialer.Events for a dialer.
package secevent

import (
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gopcua/opcua/ua"
)

// Severity ranks an event.
type Severity int

const (
	// Info is an expected event recorded for audit, e.g. an accepted connection.
	Info Severity = iota
	// Notice is a legitimate but security relevant operation, e.g. a write,
	// a method call or a change of the address space.
	Notice
	// Warning is a protocol violation or a rejected request that a broken
	// peer can cause as well as an attacker, e.g. a read of an unknown node.
	Warning
	// Alert is an event that is unlikely without an attack or a serious
	// misconfiguration, e.g. a failed signature, a replayed sequence number,
	// a rejected certificate, a flood or a changed MAC address.
	Alert
)

func (s Severity) String() string {
	switch s {
	case Info:
		return "info"
	case Notice:
		return "notice"
	case Warning:
		return "warning"
	case Alert:
		return "alert"
	}
	return fmt.Sprintf("severity(%d)", int(s))
}

// Kind identifies the type of an event. Kinds are stable strings so that
// they can be used as keys in log pipelines and rules.
type Kind string

// Transport and connection events.
const (
	// ConnectionAccepted reports every TCP connection to a listener,
	// before the OPC UA handshake.
	ConnectionAccepted Kind = "connection.accepted"
	// ConnectionRejected reports a TCP connection refused by admission
	// control, e.g. a peer outside the allowed networks.
	ConnectionRejected Kind = "connection.rejected"
	// ConnectionLimit reports a connection refused because a limit on
	// concurrent connections or handshakes was reached, or the process ran
	// out of file descriptors: connection exhaustion.
	ConnectionLimit Kind = "connection.limit"
	// ConnectionFlood reports a peer opening connections faster than the
	// configured rate.
	ConnectionFlood Kind = "connection.flood"
	// HandshakeFailed reports a connection that did not complete the
	// Hello/Acknowledge handshake: a timeout, a wrong first message or an
	// invalid Hello.
	HandshakeFailed Kind = "connection.handshake_failed"
	// MACChanged reports that the MAC address behind a peer's IP address
	// differs from the one seen before: a hint of ARP or NDP spoofing.
	MACChanged Kind = "connection.mac_changed"
	// ReverseHello reports a ReverseHello received by a listener.
	ReverseHello Kind = "connection.reverse_hello"
)

// Message level events.
const (
	// MalformedMessage reports a message, header or field that cannot be
	// decoded or violates the protocol.
	MalformedMessage Kind = "message.malformed"
	// OversizedMessage reports a message larger than the negotiated
	// buffers or with more chunks than allowed.
	OversizedMessage Kind = "message.oversized"
	// SequenceError reports a SequenceNumber that is not the successor of
	// the previous one: a replayed, dropped or reordered chunk.
	SequenceError Kind = "message.sequence_error"
	// SecurityCheckFailed reports a message whose signature or encryption
	// did not verify, or a secure channel renewal that changed its
	// security policy or certificate.
	SecurityCheckFailed Kind = "message.security_check_failed"
	// CertificateRejected reports a peer certificate that could not be
	// parsed, has an unsupported key or was rejected by the validator.
	CertificateRejected Kind = "message.certificate_rejected"
	// UnknownChannel reports a message for a SecureChannelID or a
	// security token that is not known on this connection.
	UnknownChannel Kind = "message.unknown_channel"
	// UnsolicitedResponse reports a response that matches no pending
	// request, or a response sent to a server.
	UnsolicitedResponse Kind = "message.unsolicited_response"
	// RenewStorm reports a peer renewing its secure channel faster than
	// the configured rate: the OPC UA equivalent of a keep alive storm.
	RenewStorm Kind = "message.renew_storm"
)

// Service level events.
const (
	// UnknownSession reports a request with an authentication token that
	// matches no session.
	UnknownSession Kind = "service.unknown_session"
	// AuthenticationFailed reports a session that failed to activate.
	AuthenticationFailed Kind = "service.authentication_failed"
	// SessionLimit reports a session refused because the server reached
	// its session limit.
	SessionLimit Kind = "service.session_limit"
	// UnknownCommand reports a request for a service the server does not
	// support or a call of a method that does not exist.
	UnknownCommand Kind = "service.unknown_command"
	// UnknownNode reports an operation on a node, namespace or attribute
	// that does not exist.
	UnknownNode Kind = "service.unknown_node"
	// AddressScan reports a peer that produced many UnknownNode events in
	// a short time: an address space scan.
	AddressScan Kind = "service.address_scan"
	// OversizedRequest reports a request with more operations than the
	// server allows.
	OversizedRequest Kind = "service.oversized_request"
	// TypeMismatch reports a write whose value has the wrong data type.
	TypeMismatch Kind = "service.type_mismatch"
	// AccessDenied reports an operation refused by the access level of a
	// node, e.g. a write to a read only variable.
	AccessDenied Kind = "service.access_denied"
	// RequestRejected reports any other request the server rejected.
	RequestRejected Kind = "service.request_rejected"
	// RequestFlood reports a secure channel sending requests faster than
	// the configured rate.
	RequestFlood Kind = "service.request_flood"
	// ParameterChange reports a write to an attribute.
	ParameterChange Kind = "service.parameter_change"
	// MethodCall reports a method call. Calls of methods that control the
	// server or a program (state changes, start, halt, reset), transfer
	// files or change the security configuration have Severity Alert.
	MethodCall Kind = "service.method_call"
	// NodeManagement reports a request that adds or deletes nodes or
	// references.
	NodeManagement Kind = "service.node_management"
	// UnusualService reports a rarely used service, e.g. RegisterServer,
	// TransferSubscriptions, HistoryUpdate or Cancel.
	UnusualService Kind = "service.unusual"
)

// Event is a security relevant protocol event.
//
// Fields that do not apply to an event are zero.
type Event struct {
	// Time is when the event was detected.
	Time time.Time
	// Kind is the type of the event.
	Kind Kind
	// Severity ranks the event.
	Severity Severity

	// Local and Remote are the addresses of the connection.
	Local, Remote net.Addr
	// RemoteMAC is the MAC address of the peer, when it is on a directly
	// attached network and the platform can look it up.
	RemoteMAC net.HardwareAddr
	// PreviousMAC is the MAC address seen before for the same IP address.
	// Only set for MACChanged.
	PreviousMAC net.HardwareAddr

	// ConnID is the id of the uacp connection.
	ConnID uint32
	// SecureChannelID is the id of the secure channel.
	SecureChannelID uint32
	// RequestID is the id of the request in the secure channel.
	RequestID uint32
	// Service is the name of the service request, e.g. "ReadRequest".
	Service string
	// NodeID is the node the operation addressed.
	NodeID *ua.NodeID
	// ObjectID is the object a method was called on.
	ObjectID *ua.NodeID
	// AttributeID is the attribute the operation addressed.
	AttributeID ua.AttributeID
	// Status is the status code the stack answered with, if any.
	Status ua.StatusCode

	// Detail is a human readable description.
	Detail string
	// Err is the underlying error, if any.
	Err error
}

// String formats the event for a log line.
func (e Event) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s", e.Severity, e.Kind)
	if e.Remote != nil {
		fmt.Fprintf(&b, " remote=%s", e.Remote)
	}
	if len(e.RemoteMAC) > 0 {
		fmt.Fprintf(&b, " mac=%s", e.RemoteMAC)
	}
	if len(e.PreviousMAC) > 0 {
		fmt.Fprintf(&b, " previous_mac=%s", e.PreviousMAC)
	}
	if e.ConnID != 0 {
		fmt.Fprintf(&b, " conn=%d", e.ConnID)
	}
	if e.SecureChannelID != 0 {
		fmt.Fprintf(&b, " channel=%d", e.SecureChannelID)
	}
	if e.RequestID != 0 {
		fmt.Fprintf(&b, " request=%d", e.RequestID)
	}
	if e.Service != "" {
		fmt.Fprintf(&b, " service=%s", e.Service)
	}
	if e.ObjectID != nil {
		fmt.Fprintf(&b, " object=%s", e.ObjectID)
	}
	if e.NodeID != nil {
		fmt.Fprintf(&b, " node=%s", e.NodeID)
	}
	if e.AttributeID != 0 {
		fmt.Fprintf(&b, " attribute=%d", e.AttributeID)
	}
	if e.Status != 0 {
		fmt.Fprintf(&b, " status=%s", e.Status)
	}
	if e.Detail != "" {
		fmt.Fprintf(&b, " detail=%q", e.Detail)
	}
	if e.Err != nil {
		fmt.Fprintf(&b, " err=%q", e.Err.Error())
	}
	return b.String()
}

// Handler receives events. See the package documentation for the rules a
// handler must follow.
type Handler func(Event)

// Emit calls h with e, filling in e.Time if it is zero. It is a no-op if h
// is nil. A panic in h is recovered, so a faulty handler cannot take down
// the goroutine that serves a connection.
func (h Handler) Emit(e Event) {
	if h == nil {
		return
	}
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	defer func() { _ = recover() }()
	h(e)
}

// AsyncHandler is a Handler that hands events to a goroutine through a
// bounded queue. Create it with Async.
type AsyncHandler struct {
	ch      chan Event
	dropped atomic.Uint64
	done    chan struct{}
}

// Async returns a handler that queues up to size events and delivers them to
// h on a separate goroutine, so that a slow h does not slow down the
// protocol. Events that do not fit in the queue are dropped and counted;
// dropping is preferred over blocking because an attacker controls the rate
// of most events. Call Close to stop the goroutine after the last event.
func Async(h Handler, size int) *AsyncHandler {
	if size <= 0 {
		size = 1024
	}
	a := &AsyncHandler{ch: make(chan Event, size), done: make(chan struct{})}
	go func() {
		defer close(a.done)
		for e := range a.ch {
			h.Emit(e)
		}
	}()
	return a
}

// Handle queues e. Pass a.Handle where a Handler is expected.
func (a *AsyncHandler) Handle(e Event) {
	select {
	case a.ch <- e:
	default:
		a.dropped.Add(1)
	}
}

// Dropped returns the number of events dropped because the queue was full.
func (a *AsyncHandler) Dropped() uint64 { return a.dropped.Load() }

// Close stops accepting events and waits until the queued ones are
// delivered. Handle must not be called after Close.
func (a *AsyncHandler) Close() {
	close(a.ch)
	<-a.done
}

// Multi returns a handler that passes every event to each of hs.
func Multi(hs ...Handler) Handler {
	return func(e Event) {
		for _, h := range hs {
			h.Emit(e)
		}
	}
}

// ServiceName returns the short name of a service request or response type,
// e.g. "ReadRequest" for a *ua.ReadRequest.
func ServiceName(v any) string {
	if v == nil {
		return ""
	}
	s := fmt.Sprintf("%T", v)
	if i := strings.LastIndexByte(s, '.'); i >= 0 {
		s = s[i+1:]
	}
	return strings.TrimPrefix(s, "*")
}

// Copyright 2018-2026 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package server

import (
	"crypto/x509"
	"fmt"
	"net/netip"
	"strconv"
	"time"

	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/secevent"
	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/uacp"
	"github.com/gopcua/opcua/uasc"
)

// Default detection thresholds of the server. They are reported, not
// enforced, unless an option sets Enforce.
var (
	// DefaultRequestRateLimit is the per secure channel request rate above
	// which a secevent.RequestFlood is reported.
	DefaultRequestRateLimit = secevent.RateLimit{Max: 1000, Window: time.Second}

	// DefaultAddressScanLimit is the number of operations on unknown nodes
	// per secure channel above which a secevent.AddressScan is reported.
	DefaultAddressScanLimit = secevent.RateLimit{Max: 50, Window: 10 * time.Second}
)

// securityConfig holds the security options of a server.
type securityConfig struct {
	events      secevent.Handler
	listen      []uacp.ListenOption
	reqRate     secevent.RateLimit
	scanRate    secevent.RateLimit
	renewRate   secevent.RateLimit
	maxSessions int
	verifyCert  func(*x509.Certificate) error
}

// SecurityEventHandler sets the handler that receives the security events of
// the server: from its listener, its connections, its secure channels and
// its services. See package secevent.
func SecurityEventHandler(h secevent.Handler) Option {
	return func(s *serverConfig) { s.sec.events = h }
}

// AllowedPeers restricts the clients that may connect to those whose IP
// address is in one of prefixes. Connections from other addresses are
// closed and reported as secevent.ConnectionRejected.
func AllowedPeers(prefixes ...netip.Prefix) Option {
	return func(s *serverConfig) {
		s.sec.listen = append(s.sec.listen, uacp.WithAllowedPeers(prefixes...))
	}
}

// MaxConnections bounds the open connections, in total and per client IP
// address, against connection exhaustion. A bound <= 0 disables it; both
// are disabled by default.
func MaxConnections(total, perIP int) Option {
	return func(s *serverConfig) {
		s.sec.listen = append(s.sec.listen, uacp.WithMaxConnections(total, perIP))
	}
}

// ConnectionRateLimit sets the per client IP address connection rate above
// which a secevent.ConnectionFlood is reported, and if l.Enforce is set,
// connections are refused. The default is uacp.DefaultConnectionRateLimit.
func ConnectionRateLimit(l secevent.RateLimit) Option {
	return func(s *serverConfig) {
		s.sec.listen = append(s.sec.listen, uacp.WithConnectionRateLimit(l))
	}
}

// HandshakeTimeout sets how long a client has to complete the
// Hello/Acknowledge handshake after it connects. The default is
// uacp.DefaultHandshakeTimeout.
func HandshakeTimeout(d time.Duration) Option {
	return func(s *serverConfig) {
		s.sec.listen = append(s.sec.listen, uacp.WithHandshakeTimeout(d))
	}
}

// MaxPendingHandshakes bounds the connections that have not completed the
// handshake. The default is uacp.DefaultMaxPendingHandshakes.
func MaxPendingHandshakes(n int) Option {
	return func(s *serverConfig) {
		s.sec.listen = append(s.sec.listen, uacp.WithMaxPendingHandshakes(n))
	}
}

// RequestRateLimit sets the per secure channel request rate above which a
// secevent.RequestFlood is reported, and if l.Enforce is set, requests are
// answered with Bad_TooManyOperations without being processed. The default
// is DefaultRequestRateLimit.
func RequestRateLimit(l secevent.RateLimit) Option {
	return func(s *serverConfig) { s.sec.reqRate = l }
}

// AddressScanLimit sets the number of operations on unknown nodes per
// secure channel and window above which a secevent.AddressScan is
// reported. The default is DefaultAddressScanLimit.
func AddressScanLimit(l secevent.RateLimit) Option {
	return func(s *serverConfig) { s.sec.scanRate = l }
}

// RenewRateLimit sets the per secure channel OpenSecureChannel rate above
// which a secevent.RenewStorm is reported. The default is
// uasc.DefaultRenewRateLimit.
func RenewRateLimit(l secevent.RateLimit) Option {
	return func(s *serverConfig) { s.sec.renewRate = l }
}

// MaxSessions bounds the number of sessions. CreateSession beyond the bound
// fails with Bad_TooManySessions and is reported as secevent.SessionLimit.
// n <= 0, the default, means no bound.
func MaxSessions(n int) Option {
	return func(s *serverConfig) { s.sec.maxSessions = n }
}

// CertificateValidator sets a function that checks the certificate of each
// client, from its OpenSecureChannel request and its CreateSession request.
// A non-nil error rejects the certificate with Bad_CertificateUntrusted and
// reports a secevent.CertificateRejected.
func CertificateValidator(f func(*x509.Certificate) error) Option {
	return func(s *serverConfig) { s.sec.verifyCert = f }
}

// MaxNodesPerRead sets the maximum number of nodes in a Read request, which
// the server advertises in its OperationLimits. A larger Read fails with
// Bad_TooManyOperations and is reported as secevent.OversizedRequest. 0
// means no limit.
func MaxNodesPerRead(n uint32) Option {
	return func(s *serverConfig) { s.cap.OperationalLimits.MaxNodesPerRead = n }
}

// configureChannel applies the security options to the configuration of a
// new secure channel.
func (s *Server) configureChannel(cfg *uasc.Config) {
	cfg.VerifyRemoteCertificate = s.cfg.sec.verifyCert
	cfg.RenewRateLimit = s.cfg.sec.renewRate
}

// emit reports e through the secure channel, which adds the connection
// details, or straight to the handler when there is no channel.
func (s *Server) emit(sc *uasc.SecureChannel, e secevent.Event) {
	if s.cfg.sec.events == nil {
		return
	}
	if sc != nil {
		sc.Emit(e)
		return
	}
	s.cfg.sec.events.Emit(e)
}

func channelKey(sc *uasc.SecureChannel, channelID uint32) string {
	if sc != nil && sc.Conn() != nil {
		return strconv.FormatUint(uint64(sc.Conn().ID()), 10) + "/" + strconv.FormatUint(uint64(channelID), 10)
	}
	return strconv.FormatUint(uint64(channelID), 10)
}

// sessionless lists the services a client calls without a session.
var sessionless = map[uint16]bool{
	id.FindServersRequest_Encoding_DefaultBinary:          true,
	id.FindServersOnNetworkRequest_Encoding_DefaultBinary: true,
	id.GetEndpointsRequest_Encoding_DefaultBinary:         true,
	id.RegisterServerRequest_Encoding_DefaultBinary:       true,
	id.RegisterServer2Request_Encoding_DefaultBinary:      true,
	id.CreateSessionRequest_Encoding_DefaultBinary:        true,
	// ActivateSession reports an unknown session as an authentication
	// failure instead.
	id.ActivateSessionRequest_Encoding_DefaultBinary: true,
}

// auditRequest reports the security relevant aspects of a request before it
// is handled. It returns a status other than StatusOK when the request must
// be refused without being handled.
func (s *Server) auditRequest(sc *uasc.SecureChannel, channelID, reqID uint32, req ua.Request) ua.StatusCode {
	if s.cfg.sec.events == nil && !s.reqRate.Limit().Enforce {
		return ua.StatusOK
	}
	svc := secevent.ServiceName(req)

	if exceeded, first := s.reqRate.Hit(channelKey(sc, channelID), time.Now()); exceeded {
		lim := s.reqRate.Limit()
		if first {
			s.emit(sc, secevent.Event{Kind: secevent.RequestFlood, Severity: secevent.Alert, RequestID: reqID, Service: svc, Detail: fmt.Sprintf("more than %d requests in %s", lim.Max, lim.Window)})
		}
		if lim.Enforce {
			return ua.StatusBadTooManyOperations
		}
	}

	if s.cfg.sec.events == nil {
		return ua.StatusOK
	}

	typeID := ua.ServiceTypeID(req)
	if hdr := req.Header(); hdr != nil && !sessionless[typeID] && s.sb.Session(hdr.AuthenticationToken) == nil {
		s.emit(sc, secevent.Event{Kind: secevent.UnknownSession, Severity: secevent.Warning, RequestID: reqID, Service: svc, Status: ua.StatusBadSessionIDInvalid, Detail: "request with an unknown authentication token"})
	}

	notice := func(kind secevent.Kind, detail string) {
		s.emit(sc, secevent.Event{Kind: kind, Severity: secevent.Notice, RequestID: reqID, Service: svc, Detail: detail})
	}

	switch r := req.(type) {
	case *ua.CallRequest:
		for _, m := range r.MethodsToCall {
			if m == nil {
				continue
			}
			s.auditMethodCall(sc, reqID, m)
		}
	case *ua.AddNodesRequest:
		notice(secevent.NodeManagement, fmt.Sprintf("add %d nodes", len(r.NodesToAdd)))
	case *ua.DeleteNodesRequest:
		for _, n := range r.NodesToDelete {
			if n != nil {
				s.emit(sc, secevent.Event{Kind: secevent.NodeManagement, Severity: secevent.Notice, RequestID: reqID, Service: svc, NodeID: n.NodeID, Detail: "delete node"})
			}
		}
	case *ua.AddReferencesRequest:
		notice(secevent.NodeManagement, fmt.Sprintf("add %d references", len(r.ReferencesToAdd)))
	case *ua.DeleteReferencesRequest:
		notice(secevent.NodeManagement, fmt.Sprintf("delete %d references", len(r.ReferencesToDelete)))
	case *ua.RegisterServerRequest, *ua.RegisterServer2Request:
		notice(secevent.UnusualService, "server registration")
	case *ua.TransferSubscriptionsRequest:
		notice(secevent.UnusualService, fmt.Sprintf("transfer of %d subscriptions", len(r.SubscriptionIDs)))
	case *ua.HistoryUpdateRequest:
		notice(secevent.UnusualService, "history update")
	case *ua.CancelRequest:
		notice(secevent.UnusualService, "cancel")
	case *ua.QueryFirstRequest, *ua.QueryNextRequest:
		notice(secevent.UnusualService, "query")
	}
	return ua.StatusOK
}

// controlMethods classifies methods by their BrowseName: calls of these
// control the server or a program, transfer files, or change the security
// configuration, and are reported with Severity Alert.
var controlMethods = map[string]string{
	"RequestServerStateChange": "server state change",
	"Shutdown":                 "server state change",
	"Start":                    "program control",
	"Suspend":                  "program control",
	"Resume":                   "program control",
	"Halt":                     "program control",
	"Reset":                    "program control",
	"Open":                     "file transfer",
	"OpenWithMasks":            "file transfer",
	"Read":                     "file transfer",
	"Write":                    "file transfer",
	"Close":                    "file transfer",
	"CloseAndUpdate":           "file transfer",
	"SetPosition":              "file transfer",
	"GetPosition":              "file transfer",
	"CreateFile":               "file transfer",
	"CreateDirectory":          "file transfer",
	"DeleteFileSystemObject":   "file transfer",
	"MoveOrCopy":               "file transfer",
	"UpdateCertificate":        "security configuration",
	"ApplyChanges":             "security configuration",
	"CreateSigningRequest":     "security configuration",
	"AddCertificate":           "security configuration",
	"RemoveCertificate":        "security configuration",
	"GetRejectedList":          "security configuration",
}

// controlMethodIDs classifies the well-known methods of namespace 0, for
// servers whose address space does not carry them.
var controlMethodIDs = map[uint32]string{
	id.Server_RequestServerStateChange:          "server state change",
	id.ServerType_RequestServerStateChange:      "server state change",
	id.ProgramStateMachineType_Start:            "program control",
	id.ProgramStateMachineType_Suspend:          "program control",
	id.ProgramStateMachineType_Resume:           "program control",
	id.ProgramStateMachineType_Halt:             "program control",
	id.ProgramStateMachineType_Reset:            "program control",
	id.FileType_Open:                            "file transfer",
	id.FileType_Read:                            "file transfer",
	id.FileType_Write:                           "file transfer",
	id.FileType_Close:                           "file transfer",
	id.FileType_SetPosition:                     "file transfer",
	id.FileDirectoryType_CreateFile:             "file transfer",
	id.FileDirectoryType_CreateDirectory:        "file transfer",
	id.FileDirectoryType_DeleteFileSystemObject: "file transfer",
	id.FileDirectoryType_MoveOrCopy:             "file transfer",
	id.ServerConfiguration_UpdateCertificate:    "security configuration",
	id.ServerConfiguration_ApplyChanges:         "security configuration",
	id.ServerConfiguration_CreateSigningRequest: "security configuration",
}

func (s *Server) auditMethodCall(sc *uasc.SecureChannel, reqID uint32, m *ua.CallMethodRequest) {
	ev := secevent.Event{
		Kind:      secevent.MethodCall,
		Severity:  secevent.Notice,
		RequestID: reqID,
		Service:   "CallRequest",
		ObjectID:  m.ObjectID,
		NodeID:    m.MethodID,
		Detail:    fmt.Sprintf("method call with %d arguments", len(m.InputArguments)),
	}
	var category string
	if m.MethodID != nil {
		if m.MethodID.Namespace() == 0 {
			category = controlMethodIDs[m.MethodID.IntID()]
		}
		n := s.Node(m.MethodID)
		if n == nil {
			s.emit(sc, secevent.Event{Kind: secevent.UnknownCommand, Severity: secevent.Warning, RequestID: reqID, Service: "CallRequest", ObjectID: m.ObjectID, NodeID: m.MethodID, Status: ua.StatusBadMethodInvalid, Detail: "call of an unknown method"})
		} else if name := n.BrowseName(); name != nil && category == "" {
			category = controlMethods[name.Name]
		}
	}
	if category != "" {
		ev.Severity = secevent.Alert
		ev.Detail = category + ": " + ev.Detail
	}
	s.emit(sc, ev)
}

// auditResponse reports the security relevant outcome of a request: the
// rejection of the request, and the status of each of its operations.
func (s *Server) auditResponse(sc *uasc.SecureChannel, reqID uint32, req ua.Request, resp ua.Response, err error) {
	if s.cfg.sec.events == nil {
		return
	}
	svc := secevent.ServiceName(req)

	status := ua.StatusOK
	if err != nil {
		if sc, ok := err.(ua.StatusCode); ok {
			status = sc
		} else {
			status = ua.StatusBadUnexpectedError
		}
	} else if resp != nil && resp.Header() != nil {
		status = resp.Header().ServiceResult
	}

	if status != ua.StatusOK && status != ua.StatusGood {
		ev := secevent.Event{Kind: secevent.RequestRejected, Severity: secevent.Warning, RequestID: reqID, Service: svc, Status: status, Err: err}
		switch status {
		case ua.StatusBadServiceUnsupported, ua.StatusBadRequestTypeInvalid:
			ev.Kind, ev.Detail = secevent.UnknownCommand, "service not supported"
		case ua.StatusBadTooManyOperations, ua.StatusBadTooManySessions:
			// Reported where the limit is checked.
			return
		case ua.StatusBadSessionIDInvalid, ua.StatusBadSecurityChecksFailed, ua.StatusBadIdentityTokenInvalid,
			ua.StatusBadIdentityTokenRejected, ua.StatusBadUserAccessDenied, ua.StatusBadCertificateInvalid,
			ua.StatusBadCertificateUntrusted:
			if _, ok := req.(*ua.ActivateSessionRequest); ok {
				ev.Kind, ev.Severity, ev.Detail = secevent.AuthenticationFailed, secevent.Alert, "session activation failed"
			}
		}
		s.emit(sc, ev)
		return
	}

	op := func(kind secevent.Kind, sev secevent.Severity, n *ua.NodeID, attr ua.AttributeID, st ua.StatusCode, detail string) {
		s.emit(sc, secevent.Event{Kind: kind, Severity: sev, RequestID: reqID, Service: svc, NodeID: n, AttributeID: attr, Status: st, Detail: detail})
		if kind == secevent.UnknownNode {
			if exceeded, first := s.scanRate.Hit(channelKey(sc, 0), time.Now()); exceeded && first {
				lim := s.scanRate.Limit()
				s.emit(sc, secevent.Event{Kind: secevent.AddressScan, Severity: secevent.Alert, RequestID: reqID, Service: svc, Detail: fmt.Sprintf("more than %d operations on unknown nodes in %s", lim.Max, lim.Window)})
			}
		}
	}

	// classify reports an operation's status, and returns whether it did.
	classify := func(n *ua.NodeID, attr ua.AttributeID, st ua.StatusCode) bool {
		switch st {
		case ua.StatusBadNodeIDUnknown, ua.StatusBadNodeIDInvalid, ua.StatusBadAttributeIDInvalid:
			op(secevent.UnknownNode, secevent.Warning, n, attr, st, "operation on an unknown node or attribute")
		case ua.StatusBadUserAccessDenied, ua.StatusBadNotReadable, ua.StatusBadNotWritable:
			op(secevent.AccessDenied, secevent.Warning, n, attr, st, "operation refused by the access level")
		case ua.StatusBadTypeMismatch:
			op(secevent.TypeMismatch, secevent.Warning, n, attr, st, "value of the wrong data type")
		default:
			return false
		}
		return true
	}

	switch r := req.(type) {
	case *ua.ReadRequest:
		res, ok := resp.(*ua.ReadResponse)
		if !ok {
			return
		}
		for i, n := range r.NodesToRead {
			if i < len(res.Results) && n != nil && res.Results[i] != nil {
				classify(n.NodeID, n.AttributeID, res.Results[i].Status)
			}
		}
	case *ua.WriteRequest:
		res, ok := resp.(*ua.WriteResponse)
		if !ok {
			return
		}
		for i, n := range r.NodesToWrite {
			if n == nil {
				continue
			}
			st := ua.StatusBad
			if i < len(res.Results) {
				st = res.Results[i]
			}
			if classify(n.NodeID, n.AttributeID, st) {
				continue
			}
			if st == ua.StatusOK {
				op(secevent.ParameterChange, secevent.Notice, n.NodeID, n.AttributeID, st, "attribute written")
			} else {
				op(secevent.RequestRejected, secevent.Warning, n.NodeID, n.AttributeID, st, "write rejected")
			}
		}
	case *ua.BrowseRequest:
		res, ok := resp.(*ua.BrowseResponse)
		if !ok {
			return
		}
		for i, n := range r.NodesToBrowse {
			if i < len(res.Results) && n != nil && res.Results[i] != nil {
				classify(n.NodeID, 0, res.Results[i].StatusCode)
			}
		}
	case *ua.CreateMonitoredItemsRequest:
		res, ok := resp.(*ua.CreateMonitoredItemsResponse)
		if !ok {
			return
		}
		for i, it := range r.ItemsToCreate {
			if i < len(res.Results) && it != nil && it.ItemToMonitor != nil && res.Results[i] != nil {
				classify(it.ItemToMonitor.NodeID, it.ItemToMonitor.AttributeID, res.Results[i].StatusCode)
			}
		}
	case *ua.CallRequest:
		res, ok := resp.(*ua.CallResponse)
		if !ok {
			return
		}
		for i, m := range r.MethodsToCall {
			if i >= len(res.Results) || m == nil || res.Results[i] == nil {
				continue
			}
			switch st := res.Results[i].StatusCode; st {
			case ua.StatusOK:
			case ua.StatusBadMethodInvalid, ua.StatusBadNodeIDUnknown:
				s.emit(sc, secevent.Event{Kind: secevent.UnknownCommand, Severity: secevent.Warning, RequestID: reqID, Service: svc, ObjectID: m.ObjectID, NodeID: m.MethodID, Status: st, Detail: "call of an unknown method"})
			case ua.StatusBadTypeMismatch, ua.StatusBadArgumentsMissing, ua.StatusBadTooManyArguments, ua.StatusBadInvalidArgument:
				s.emit(sc, secevent.Event{Kind: secevent.TypeMismatch, Severity: secevent.Warning, RequestID: reqID, Service: svc, ObjectID: m.ObjectID, NodeID: m.MethodID, Status: st, Detail: "method called with wrong arguments"})
			default:
				s.emit(sc, secevent.Event{Kind: secevent.RequestRejected, Severity: secevent.Warning, RequestID: reqID, Service: svc, ObjectID: m.ObjectID, NodeID: m.MethodID, Status: st, Detail: "method call rejected"})
			}
		}
	}
}

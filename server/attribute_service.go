package server

import (
	"fmt"
	"time"

	"github.com/gopcua/opcua/secevent"
	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/uasc"
)

// AttributeService implements the Attribute Service Set.
//
// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.10
type AttributeService struct {
	srv *Server
}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.10.2
func (s *AttributeService) Read(sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	if s.srv.cfg.logger != nil {
		s.srv.cfg.logger.Debug("Handling %T", r)
	}

	req, err := safeReq[*ua.ReadRequest](r)
	if err != nil {
		return nil, err
	}

	// Enforce the limit the server advertises in its OperationLimits
	// (OPC 10000-5 §6.3.11): a client that ignores it is either broken
	// or trying to make the server do unbounded work.
	if max := s.srv.cfg.cap.OperationalLimits.MaxNodesPerRead; max > 0 && uint32(len(req.NodesToRead)) > max {
		s.srv.emit(sc, secevent.Event{
			Kind:      secevent.OversizedRequest,
			Severity:  secevent.Warning,
			RequestID: reqID,
			Service:   "ReadRequest",
			Status:    ua.StatusBadTooManyOperations,
			Detail:    fmt.Sprintf("read of %d nodes exceeds MaxNodesPerRead %d", len(req.NodesToRead), max),
		})
		return nil, ua.StatusBadTooManyOperations
	}

	results := make([]*ua.DataValue, len(req.NodesToRead))
	for i, n := range req.NodesToRead {
		if s.srv.cfg.logger != nil {
			s.srv.cfg.logger.Debug("read: node=%s attr=%s", n.NodeID, n.AttributeID)
		}

		ns, err := s.srv.Namespace(int(n.NodeID.Namespace()))
		if err != nil {
			results[i] = &ua.DataValue{
				EncodingMask:    ua.DataValueServerTimestamp | ua.DataValueStatusCode,
				ServerTimestamp: time.Now(),
				Status:          ua.StatusBad,
			}
			s.srv.emit(sc, secevent.Event{
				Kind:        secevent.UnknownNode,
				Severity:    secevent.Warning,
				RequestID:   reqID,
				Service:     "ReadRequest",
				NodeID:      n.NodeID,
				AttributeID: n.AttributeID,
				Status:      ua.StatusBad,
				Detail:      "read in an unknown namespace",
			})
			continue
		}
		results[i] = ns.Attribute(n.NodeID, n.AttributeID)

	}

	response := &ua.ReadResponse{
		ResponseHeader: responseHeader(req.RequestHeader.RequestHandle, ua.StatusOK),
		Results:        results,
	}

	return response, nil
}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.10.3
func (s *AttributeService) HistoryRead(sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	if s.srv.cfg.logger != nil {
		s.srv.cfg.logger.Debug("Handling %T", r)
	}

	req, err := safeReq[*ua.HistoryReadRequest](r)
	if err != nil {
		return nil, err
	}
	return serviceUnsupported(req.RequestHeader), nil
}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.10.4
func (s *AttributeService) Write(sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {

	req, err := safeReq[*ua.WriteRequest](r)
	if err != nil {
		return nil, err
	}

	status := make([]ua.StatusCode, len(req.NodesToWrite))

	for i := range req.NodesToWrite {
		n := req.NodesToWrite[i]
		if s.srv.cfg.logger != nil {
			s.srv.cfg.logger.Debug("write: node=%s attr=%v", n.NodeID, n.AttributeID)
		}

		ns, err := s.srv.Namespace(int(n.NodeID.Namespace()))
		if err != nil {
			status[i] = ua.StatusBadNodeIDUnknown
			continue
		}

		status[i] = ns.SetAttribute(n.NodeID, n.AttributeID, n.Value)

	}
	response := &ua.WriteResponse{
		ResponseHeader: &ua.ResponseHeader{
			Timestamp:          time.Now(),
			RequestHandle:      req.RequestHeader.RequestHandle,
			ServiceResult:      ua.StatusOK,
			ServiceDiagnostics: &ua.DiagnosticInfo{},
			StringTable:        []string{},
			AdditionalHeader:   ua.NewExtensionObject(nil),
		},
		Results:         status,
		DiagnosticInfos: []*ua.DiagnosticInfo{},
	}

	return response, nil

}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.10.5
func (s *AttributeService) HistoryUpdate(sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	if s.srv.cfg.logger != nil {
		s.srv.cfg.logger.Debug("Handling %T", r)
	}

	req, err := safeReq[*ua.HistoryUpdateRequest](r)
	if err != nil {
		return nil, err
	}
	return serviceUnsupported(req.RequestHeader), nil
}

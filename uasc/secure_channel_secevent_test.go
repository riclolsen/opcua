// Copyright 2018-2026 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package uasc

import (
	"context"
	"crypto/x509"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/gopcua/opcua/secevent"
	"github.com/gopcua/opcua/ua"
)

// eventRecorder collects the events a handler receives.
type eventRecorder struct {
	mu     sync.Mutex
	events []secevent.Event
}

func (r *eventRecorder) handle(e secevent.Event) {
	r.mu.Lock()
	r.events = append(r.events, e)
	r.mu.Unlock()
}

func (r *eventRecorder) kinds() []secevent.Kind {
	r.mu.Lock()
	defer r.mu.Unlock()
	var ks []secevent.Kind
	for _, e := range r.events {
		ks = append(ks, e.Kind)
	}
	return ks
}

func (r *eventRecorder) find(k secevent.Kind) (secevent.Event, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range r.events {
		if e.Kind == k {
			return e, true
		}
	}
	return secevent.Event{}, false
}

// A chunk whose SequenceNumber skips ahead, or repeats the previous one as a
// replay does, is reported as a SequenceError with the channel's details.
func TestSequenceErrorIsReported(t *testing.T) {
	s, peer := newSequenceNumberTestChannel(t)
	rec := &eventRecorder{}
	s.c.SetEventHandler(rec.handle)

	writeSequenceNumberChunk(t, peer, 10, 1)
	_, err := s.readChunk()
	require.NoError(t, err)

	// replay of the same chunk
	writeSequenceNumberChunk(t, peer, 10, 1)
	_, err = s.readChunk()
	require.ErrorIs(t, err, ua.StatusBadSecurityChecksFailed)

	e, ok := rec.find(secevent.SequenceError)
	require.True(t, ok, "no SequenceError in %v", rec.kinds())
	require.Equal(t, secevent.Alert, e.Severity)
	require.Equal(t, uint32(1), e.SecureChannelID)
	require.Equal(t, ua.StatusBadSequenceNumberInvalid, e.Status)
	require.NotNil(t, e.Remote)
	require.NotZero(t, e.ConnID)
}

// A MSG chunk that names a TokenId the channel never issued is reported.
func TestUnknownTokenIDIsReported(t *testing.T) {
	s, peer := newSequenceNumberTestChannel(t)
	rec := &eventRecorder{}
	s.c.SetEventHandler(rec.handle)
	s.activeInstance.securityTokenID = 99 // the peer writes TokenId 2

	writeSequenceNumberChunk(t, peer, 1, 1)
	_, err := s.readChunk()
	require.NoError(t, err)

	e, ok := rec.find(secevent.UnknownChannel)
	require.True(t, ok, "no UnknownChannel in %v", rec.kinds())
	require.Equal(t, ua.StatusBadSecureChannelTokenUnknown, e.Status)
}

// Without a handler nothing is reported and nothing fails.
func TestNoHandlerNoEvents(t *testing.T) {
	s, peer := newSequenceNumberTestChannel(t)
	writeSequenceNumberChunk(t, peer, 10, 1)
	_, err := s.readChunk()
	require.NoError(t, err)
	writeSequenceNumberChunk(t, peer, 10, 1)
	_, err = s.readChunk()
	require.Error(t, err)
}

// A response for a RequestId the client never used is reported as
// unsolicited by the client's dispatcher.
func TestUnsolicitedResponseIsReported(t *testing.T) {
	s, peer := newSequenceNumberTestChannel(t)
	rec := &eventRecorder{}
	s.c.SetEventHandler(rec.handle)
	s.closing = make(chan struct{})
	s.disconnected = make(chan struct{})
	s.handlers = make(map[uint32]chan *MessageBody)
	s.chunks = make(map[uint32][]*MessageChunk)
	s.reqLocker = newConditionLocker()
	s.rcvLocker = newConditionLocker()
	s.errch = make(chan error, 1)
	go s.dispatcher()
	t.Cleanup(func() { close(s.closing); s.c.Close() })

	writeSequenceNumberChunk(t, peer, 1, 4711)

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if e, ok := rec.find(secevent.UnsolicitedResponse); ok {
			require.Equal(t, uint32(4711), e.RequestID)
			require.Equal(t, "ReadResponse", e.Service)
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no UnsolicitedResponse in %v", rec.kinds())
}

// A client rejects a server certificate in the OpenSecureChannel response
// that is not the endpoint's, and keeps the endpoint's certificate in its
// configuration for the next connection.
func TestClientRejectsCertificateOtherThanEndpoints(t *testing.T) {
	endpointDER, _ := genThumbprintTestCert(t, "endpoint")
	otherDER, _ := genThumbprintTestCert(t, "impostor")
	other, err := x509.ParseCertificate(otherDER)
	require.NoError(t, err)
	endpoint, err := x509.ParseCertificate(endpointDER)
	require.NoError(t, err)

	s, _ := newSequenceNumberTestChannel(t)
	s.kind = client
	rec := &eventRecorder{}
	s.c.SetEventHandler(rec.handle)

	err = s.checkRemoteCertificate(1, other, endpointDER)
	require.ErrorIs(t, err, ua.StatusBadCertificateInvalid)
	e, ok := rec.find(secevent.CertificateRejected)
	require.True(t, ok)
	require.Contains(t, e.Detail, "impostor")
	require.Nil(t, s.remoteLeaf, "a rejected certificate is not pinned")

	require.NoError(t, s.checkRemoteCertificate(1, endpoint, endpointDER))
	// a renewal must present the pinned certificate
	require.ErrorIs(t, s.checkRemoteCertificate(1, other, nil), ua.StatusBadCertificateInvalid)
}

// The validator rejects a certificate with Bad_CertificateUntrusted.
func TestCertificateValidatorRejects(t *testing.T) {
	der, _ := genThumbprintTestCert(t, "peer")
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	s, _ := newSequenceNumberTestChannel(t)
	s.kind = server
	s.cfg.VerifyRemoteCertificate = func(*x509.Certificate) error { return errors.New("not trusted") }
	require.ErrorIs(t, s.checkRemoteCertificate(1, cert, nil), ua.StatusBadCertificateUntrusted)
}

// Partial messages of many RequestIds together are bounded by
// maxUnfinishedMessages: a peer that starts messages and never finishes them
// cannot grow the buffer without bound.
func TestPartialMessagesAreBoundedAcrossRequests(t *testing.T) {
	s, peer := newSequenceNumberTestChannel(t)
	s.kind = server
	rec := &eventRecorder{}
	s.c.SetEventHandler(rec.handle)
	s.chunks = make(map[uint32][]*MessageChunk)

	// The socket buffers all of them: each chunk is a few dozen bytes.
	for i := 0; i <= maxUnfinishedMessages; i++ {
		peer.writeChunk(t, ChunkTypeIntermediate, uint32(i+1), uint32(i+1))
	}

	msg := s.Receive(context.Background())
	require.Error(t, msg.Err)
	require.Contains(t, msg.Err.Error(), "too many unfinished messages")
	_, ok := rec.find(secevent.OversizedMessage)
	require.True(t, ok)

	s.chunksMu.Lock()
	defer s.chunksMu.Unlock()
	require.Empty(t, s.chunks)
	require.Empty(t, s.chunkBytes)
}

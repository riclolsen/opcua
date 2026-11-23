// Copyright 2018-2026 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package server

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// A session nobody uses for longer than its timeout is removed, so that a
// client that vanished without CloseSession does not hold a slot of
// MaxSessions forever; a used one is kept.
func TestSessionsExpire(t *testing.T) {
	now := time.Unix(1000, 0)
	sb := newSessionBroker(nil)
	sb.clock = func() time.Time { return now }

	idle := sb.NewSession(time.Minute)
	used := sb.NewSession(time.Minute)
	require.Equal(t, 2, sb.Count())

	now = now.Add(50 * time.Second)
	sb.Touch(used.AuthTokenID)

	now = now.Add(20 * time.Second)
	require.Equal(t, 1, sb.Count())
	require.Nil(t, sb.Session(idle.AuthTokenID))
	require.Same(t, used, sb.Session(used.AuthTokenID))

	now = now.Add(2 * time.Minute)
	require.Nil(t, sb.Session(used.AuthTokenID))
	require.Equal(t, 0, sb.Count())
}

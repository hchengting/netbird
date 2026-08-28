package guard

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/peer/ice"
	"github.com/netbirdio/netbird/client/internal/stdnet"
)

type forceRelayTestNotifier struct {
	listener func()
}

func (n *forceRelayTestNotifier) SetOnReconnectedListener(listener func()) {
	n.listener = listener
}

func (n *forceRelayTestNotifier) Ready() bool {
	return true
}

type forceRelayTestICEMonitor struct {
	started chan<- struct{}
	stopped chan<- struct{}
}

func (m *forceRelayTestICEMonitor) Start(ctx context.Context, _ func()) {
	m.started <- struct{}{}
	<-ctx.Done()
	m.stopped <- struct{}{}
}

func TestSRWatcherTogglesOnlyICEMonitor(t *testing.T) {
	signalNotifier := &forceRelayTestNotifier{}
	relayNotifier := &forceRelayTestNotifier{}
	watcher := NewSRWatcher(signalNotifier, relayNotifier, nil, ice.Config{})
	monitorStarted := make(chan struct{}, 2)
	monitorStopped := make(chan struct{}, 2)
	watcher.newICEMonitor = func(stdnet.ExternalIFaceDiscover, ice.Config, time.Duration) iceMonitor {
		return &forceRelayTestICEMonitor{started: monitorStarted, stopped: monitorStopped}
	}

	watcher.Start(true)
	require.True(t, watcher.started)
	require.Nil(t, watcher.cancelIceMonitor)
	require.NotNil(t, signalNotifier.listener)
	require.NotNil(t, relayNotifier.listener)

	watcher.SetICEMonitorEnabled(true)
	require.NotNil(t, watcher.cancelIceMonitor)
	requireSignal(t, monitorStarted, "ICE monitor should start")

	watcher.SetICEMonitorEnabled(false)
	require.Nil(t, watcher.cancelIceMonitor)
	requireSignal(t, monitorStopped, "ICE monitor should stop")
	require.NotNil(t, signalNotifier.listener,
		"disabling the ICE monitor must preserve the signal reconnect listener")
	require.NotNil(t, relayNotifier.listener,
		"disabling the ICE monitor must preserve the relay reconnect listener")

	watcher.SetICEMonitorEnabled(true)
	require.NotNil(t, watcher.cancelIceMonitor, "the ICE monitor must be restartable")
	requireSignal(t, monitorStarted, "replacement ICE monitor should start")

	watcher.Close()
	requireSignal(t, monitorStopped, "replacement ICE monitor should stop")
	require.False(t, watcher.started)
	require.Nil(t, watcher.cancelIceMonitor)
	require.Nil(t, signalNotifier.listener)
	require.Nil(t, relayNotifier.listener)
}

func TestSRWatcherKeepsICEMonitorForPendingPeer(t *testing.T) {
	signalNotifier := &forceRelayTestNotifier{}
	relayNotifier := &forceRelayTestNotifier{}
	watcher := NewSRWatcher(signalNotifier, relayNotifier, nil, ice.Config{})
	monitorStarted := make(chan struct{}, 1)
	monitorStopped := make(chan struct{}, 1)
	watcher.newICEMonitor = func(stdnet.ExternalIFaceDiscover, ice.Config, time.Duration) iceMonitor {
		return &forceRelayTestICEMonitor{started: monitorStarted, stopped: monitorStopped}
	}

	watcher.Start(true)
	watcher.SetPeerICEMonitorRequired("pending-peer-a", true)
	watcher.SetPeerICEMonitorRequired("pending-peer-b", true)
	requireSignal(t, monitorStarted, "pending peer should start the ICE monitor")

	watcher.SetICEMonitorEnabled(false)
	require.NotNil(t, watcher.cancelIceMonitor,
		"disabling the base policy must not stop a monitor required by a pending peer")
	requireNoSignal(t, monitorStopped,
		"pending peer requirement should keep the ICE monitor running")

	watcher.SetPeerICEMonitorRequired("pending-peer-a", false)
	require.NotNil(t, watcher.cancelIceMonitor,
		"one pending peer must keep the shared ICE monitor running")
	requireNoSignal(t, monitorStopped,
		"ICE monitor must wait for every pending peer requirement")

	watcher.SetPeerICEMonitorRequired("pending-peer-b", false)
	requireSignal(t, monitorStopped, "ICE monitor should stop after the final requirement is released")
	watcher.Close()
}

func requireSignal(t *testing.T, ch <-chan struct{}, message string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal(message)
	}
}

func requireNoSignal(t *testing.T, ch <-chan struct{}, message string) {
	t.Helper()
	select {
	case <-ch:
		t.Fatal(message)
	case <-time.After(50 * time.Millisecond):
	}
}

package internal

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/peerstore"
)

func TestEngineSetForceRelayUpdatesClosedPeersWithoutRestart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	engine := &Engine{
		ctx:        ctx,
		syncMsgMux: &sync.Mutex{},
		config:     &EngineConfig{},
		peerStore:  peerstore.NewConnStore(),
	}
	conn, err := peer.NewConn(peer.ConnConfig{
		Key:        "remote-peer",
		LocalKey:   "local-peer",
		ForceRelay: false,
		WgConfig: peer.WgConfig{
			RemoteKey:  "remote-peer",
			AllowedIps: []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")},
		},
	}, peer.ServiceDependencies{})
	require.NoError(t, err)
	require.True(t, engine.peerStore.AddPeerConn("remote-peer", conn))

	require.NoError(t, engine.SetForceRelay(true))
	require.True(t, engine.ForceRelayEnabled())
	require.True(t, conn.ForceRelayDesired())
	require.True(t, conn.ForceRelayEnabled())
	require.False(t, conn.ForceRelayPending())

	require.NoError(t, engine.SetForceRelay(true), "idempotent update must be a no-op")
}

func TestReconfigureForceRelayPeersUsesBoundedConcurrency(t *testing.T) {
	peerCount := maxConcurrentForceRelayReconfigurations + 2
	peerKeys := make([]string, peerCount)
	for i := range peerKeys {
		peerKeys[i] = fmt.Sprintf("peer-%d", i)
	}

	started := make(chan string, peerCount)
	release := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })

	done := make(chan struct{})
	var reconfigured int
	var reconfigureErr error
	go func() {
		reconfigured, reconfigureErr = reconfigureForceRelayPeers(
			peerKeys,
			func(peerKey string) (bool, error) {
				started <- peerKey
				<-release
				return true, nil
			},
		)
		close(done)
	}()

	for i := 0; i < maxConcurrentForceRelayReconfigurations; i++ {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatalf("only %d peer reconfigurations started concurrently", i)
		}
	}
	select {
	case peerKey := <-started:
		t.Fatalf("peer %s exceeded the concurrency limit", peerKey)
	case <-time.After(50 * time.Millisecond):
	}

	releaseOnce.Do(func() { close(release) })
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("parallel peer reconfiguration did not finish")
	}
	require.NoError(t, reconfigureErr)
	require.Equal(t, peerCount, reconfigured,
		"every successful peer reconfiguration should be counted")
}

func TestReconfigureForceRelayPeersAggregatesErrorsInPeerOrder(t *testing.T) {
	peerKeys := []string{"peer-a", "peer-b", "peer-c"}
	reconfigured, err := reconfigureForceRelayPeers(
		peerKeys,
		func(peerKey string) (bool, error) {
			switch peerKey {
			case "peer-a":
				time.Sleep(20 * time.Millisecond)
				return true, nil
			case "peer-b":
				time.Sleep(10 * time.Millisecond)
				return false, errors.New("second failure")
			default:
				return false, errors.New("third failure")
			}
		},
	)

	require.Equal(t, 1, reconfigured,
		"only successful peer transitions should be counted")
	require.Error(t, err)
	errorText := err.Error()
	secondIndex := strings.Index(errorText, "reconfigure peer peer-b: second failure")
	thirdIndex := strings.Index(errorText, "reconfigure peer peer-c: third failure")
	require.GreaterOrEqual(t, secondIndex, 0,
		"the first peer error should retain its peer context")
	require.Greater(t, thirdIndex, secondIndex,
		"errors should follow peer input order rather than completion order")
}

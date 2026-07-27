//go:build windows

package main

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/funnybones69/tamizdat/internal/configurl"
	"github.com/funnybones69/tamizdat/internal/routing"
	"github.com/funnybones69/tamizdat/internal/svcipc"
	"github.com/funnybones69/tamizdat/internal/tunengine"
	"github.com/funnybones69/tamizdat/node"
	"github.com/funnybones69/tamizdat/pkg/tamizdat"
)

type windowsEngine struct {
	mu         sync.Mutex
	engine     *tunengine.Engine
	wintunPath string
}

func newWindowsEngine(wintunPath string) *windowsEngine {
	return &windowsEngine{wintunPath: wintunPath}
}

type windowsTunnelSession struct {
	client         *tamizdat.Client
	routingNode    *node.Node
	tunSession     *tunengine.Session
	routingCleanup func()
	status         tunnelStatus
	startedAt      time.Time
}

func (e *windowsEngine) Connect(ctx context.Context, req svcipc.ConnectRequest) (tunnelSession, svcipc.ConnectResponse, error) {
	e.mu.Lock()
	wintunPath := e.wintunPath
	e.mu.Unlock()
	if wintunPath == "" {
		return nil, svcipc.ConnectResponse{}, fmt.Errorf("wintun was not extracted at service start")
	}
	parsed, err := configurl.Parse(req.ConfigURI)
	if err != nil {
		return nil, svcipc.ConnectResponse{}, fmt.Errorf("config URL: %w", err)
	}
	client, err := tamizdat.NewClient(tamizdat.ClientConfig{
		ServerAddr:       parsed.ServerAddr,
		ServerName:       parsed.ServerName,
		ServerNames:      parsed.ServerNames,
		PublicKey:        parsed.PublicKey,
		MasterShortID:    parsed.MasterShortID,
		Fingerprint:      parsed.Fingerprint,
		TCPFragmentation: true,
		PoolVariant:      req.PoolVariant,
	})
	if err != nil {
		return nil, svcipc.ConnectResponse{}, fmt.Errorf("client init: %w", err)
	}

	e.mu.Lock()
	if e.engine == nil {
		e.engine, err = tunengine.New(tunengine.Options{Name: "Samizdat", MTU: 1500})
		if err != nil {
			e.mu.Unlock()
			_ = client.Close()
			return nil, svcipc.ConnectResponse{}, err
		}
	}
	eng := e.engine
	e.mu.Unlock()

	// Optional routing-rule dispatcher (xray-style). When req.RoutingConfigPath
	// is set, build a node and pass its dispatcher into tunengine; otherwise
	// the legacy single-client path is used (PA TURN 15 routing rules ignored).
	var routingNode *node.Node
	var dispatcher *node.Dispatcher
	if path := strings.TrimSpace(req.RoutingConfigPath); path != "" {
		nodeCfg, lerr := node.LoadConfig(path)
		if lerr != nil {
			_ = client.Close()
			return nil, svcipc.ConnectResponse{}, fmt.Errorf("routing-config %q load: %w", path, lerr)
		}
		n, nerr := node.New(nodeCfg)
		if nerr != nil {
			_ = client.Close()
			return nil, svcipc.ConnectResponse{}, fmt.Errorf("routing-config %q build: %w", path, nerr)
		}
		routingNode = n
		dispatcher = n.Dispatcher()
	}

	var cleanup func()
	opts := tunengine.Options{
		Name:                     "Samizdat",
		MTU:                      1500,
		Debug:                    req.Debug,
		TCPModerateReceiveBuffer: true,
		TunIP:                    "10.255.0.2",
		TunPrefix:                24,
		AutoRoute:                true,
		Dispatcher:               dispatcher,
		PostTunUp: func() error {
			c, err := routing.ConfigureAutoRouting(ctx, parsed.ServerAddr, "Samizdat", "10.255.0.2", 24, req.SelectiveRoutes, req.BypassRoutes, 5*time.Minute)
			if err != nil {
				return err
			}
			cleanup = c
			return nil
		},
	}
	sess, err := eng.Start(ctx, opts, client)
	if err != nil {
		if routingNode != nil {
			_ = routingNode.Close()
		}
		_ = client.Close()
		return nil, svcipc.ConnectResponse{}, err
	}
	st := tunnelStatus{ServerAddr: parsed.ServerAddr, RTT: -1}
	return &windowsTunnelSession{client: client, routingNode: routingNode, tunSession: sess, routingCleanup: cleanup, status: st, startedAt: time.Now()}, svcipc.ConnectResponse{ConnectionID: fmt.Sprintf("%d", time.Now().UnixNano()), ServerAddr: parsed.ServerAddr, LocalTunIP: "10.255.0.2"}, nil
}

func (e *windowsEngine) Close() error {
	e.mu.Lock()
	eng := e.engine
	e.engine = nil
	e.mu.Unlock()
	if eng != nil {
		return eng.Close()
	}
	return nil
}

func (s *windowsTunnelSession) Stop(ctx context.Context) error {
	if s.routingCleanup != nil {
		s.routingCleanup()
		s.routingCleanup = nil
	}
	if s.tunSession != nil {
		if err := s.tunSession.Stop(ctx); err != nil {
			return err
		}
	}
	if s.routingNode != nil {
		_ = s.routingNode.Close()
		s.routingNode = nil
	}
	if s.client != nil {
		return s.client.Close()
	}
	return nil
}

func (s *windowsTunnelSession) Status() tunnelStatus {
	if s.client == nil {
		return s.status
	}
	rtt := s.client.RTTProbeSnapshot()
	return tunnelStatus{ServerAddr: s.status.ServerAddr, RTT: rtt.P50Ms}
}

func (s *windowsTunnelSession) Stats() svcipc.StatsResponse {
	resp := statsFromExpvar(s.startedAt)
	if s.client == nil {
		resp.RTTMs = s.status.RTT
		return resp
	}
	rtt := s.client.RTTProbeSnapshot()
	resp.RTTMs = rtt.P50Ms
	resp.LastRTTMs = rtt.LastMs
	return resp
}

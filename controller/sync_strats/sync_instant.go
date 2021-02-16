/*
	Copyright NetFoundry, Inc.

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

	https://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
*/

package sync_strats

import (
	"encoding/json"
	"fmt"
	"github.com/golang/protobuf/proto"
	"github.com/lucsky/cuid"
	"github.com/michaelquigley/pfxlog"
	"github.com/openziti/edge/build"
	"github.com/openziti/edge/controller/env"
	"github.com/openziti/edge/controller/handler_edge_ctrl"
	"github.com/openziti/edge/controller/model"
	"github.com/openziti/edge/controller/persistence"
	"github.com/openziti/edge/pb/edge_ctrl_pb"
	"github.com/openziti/fabric/controller/network"
	"github.com/openziti/foundation/channel2"
	"github.com/openziti/foundation/storage/ast"
	"go.etcd.io/bbolt"
	"strings"
	"sync"
	"time"
)

const (
	RouterSyncStrategyInstant env.RouterSyncStrategyType = "instant"
)

var _ env.RouterSyncStrategy = &InstantStrategy{}

// Options for the instant strategy.
// - MaxQueuedRouterConnects    - max number of router connected events to buffer
// - MaxQueuedClientHellos      - max number of client hello messages to buffer
// - RouterConnectWorkerCount   - max number of workers used to process router connections
// - SyncWorkerCount            - max number of workers used to send api sessions/session data
// - RouterTxBufferSize         - max number of messages buffered to be send to a router
// - HelloSendTimeout           - the max amount of time per worker to wait to send hellos
// - SessionChunkSize           - the number of sessions to send in each message
type InstantStrategyOptions struct {
	MaxQueuedRouterConnects  int32
	MaxQueuedClientHellos    int32
	RouterConnectWorkerCount int32
	SyncWorkerCount          int32
	RouterTxBufferSize       int
	HelloSendTimeout         time.Duration
	SessionChunkSize         int
}

// Original API Session synchronization implementation. Assumes that on connect, the router requires and instant
// and full set of API Sessions. Send individual create, update, delete events for sessions after synchronization.
//
// This strategy uses a series of queus and workers to managed sychronization state. The order of events is as follows:
// 1. An edge router connects to the controller, triggering RouterConnected()
// 2. A RouterSender is created encapsulating the Edge Router, Router, and Sync State
// 3. The RouterSender is queued on the routerConnectedQueue channel which buffers up to options.MaxQueuedRouterConnects
// 4. The routerConnectedQueue is read and the edge server hello is sent
// 5. The controller waits for a client hello to be recieved via ReceiveClientHello message
// 6. The client hello is used to identity the RouterSender associated with the client and is queued on
//    the receivedClientHelloQueue channel which buffers up to options.MaxQueuedClientHellos
// 7. A startSynchronizeWorker will pick up the RouterSender from the receivedClientHelloQueue and being to
//    send data to the edge router via the RouterSender
type InstantStrategy struct {
	InstantStrategyOptions

	rtxMap *routerTxMap

	helloHandler  channel2.ReceiveHandler
	resyncHandler channel2.ReceiveHandler
	ae            *env.AppEnv

	routerConnectedQueue     chan *RouterSender
	receivedClientHelloQueue chan *RouterSender

	stop chan struct{}
}

func NewInstantStrategy(ae *env.AppEnv, options InstantStrategyOptions) *InstantStrategy {
	if options.MaxQueuedRouterConnects <= 0 {
		pfxlog.Logger().Panicf("MaxQueuedRouterConnects for InstantStrategy cannot be less than 1, got %d", options.MaxQueuedRouterConnects)
	}

	if options.MaxQueuedClientHellos <= 0 {
		pfxlog.Logger().Panicf("MaxQueuedClientHellos for InstantStrategy cannot be less than 1, got %d", options.MaxQueuedClientHellos)
	}

	if options.RouterConnectWorkerCount <= 0 {
		pfxlog.Logger().Panicf("RouterConnectWorkerCount for InstantStrategy cannot be less than 1, got %d", options.RouterConnectWorkerCount)
	}

	if options.SyncWorkerCount <= 0 {
		pfxlog.Logger().Panicf("SyncWorkerCount for InstantStrategy cannot be less than 1, got %d", options.SyncWorkerCount)
	}

	if options.RouterTxBufferSize < 0 {
		pfxlog.Logger().Panicf("RouterTxBufferSize for InstantStrategy cannot be less than 0, got %d", options.MaxQueuedRouterConnects)
	}

	if options.SessionChunkSize <= 0 {
		pfxlog.Logger().Panicf("SessionChunkSize for InstantStrategy cannot be less than 1, got %d", options.SessionChunkSize)
	}

	strategy := &InstantStrategy{
		InstantStrategyOptions: options,
		rtxMap: &routerTxMap{
			internalMap: &sync.Map{},
		},
		ae:                       ae,
		routerConnectedQueue:     make(chan *RouterSender, options.MaxQueuedRouterConnects),
		receivedClientHelloQueue: make(chan *RouterSender, options.MaxQueuedClientHellos),

		stop: make(chan struct{}, 0),
	}

	strategy.helloHandler = handler_edge_ctrl.NewHelloHandler(ae, strategy.ReceiveClientHello)
	strategy.resyncHandler = handler_edge_ctrl.NewResyncHandler(ae, strategy.ReceiveResync)

	for i := int32(0); i < options.RouterConnectWorkerCount; i++ {
		go strategy.startHandleRouterConnectWorker()
	}

	for i := int32(0); i < options.SyncWorkerCount; i++ {
		go strategy.startSynchronizeWorker()
	}

	return strategy
}
func (strategy *InstantStrategy) GetOnlineEdgeRouter(id string) (*model.EdgeRouter, env.RouterSyncStatus) {
	rtx := strategy.rtxMap.Get(id)

	if rtx != nil {
		return rtx.EdgeRouter, rtx.Status
	}

	return nil, env.RouterSyncUnknown
}

func (strategy *InstantStrategy) Status(id string) env.RouterSyncStatus {
	rtx := strategy.rtxMap.Get(id)
	if rtx == nil {
		return env.RouterSyncUnknown
	}

	return rtx.Status
}

func (strategy *InstantStrategy) Type() env.RouterSyncStrategyType {
	return RouterSyncStrategyInstant
}

func (strategy *InstantStrategy) Stop() {
	if strategy.stop != nil {
		close(strategy.stop)
		strategy.stop = nil
	}
}

func (strategy *InstantStrategy) RouterConnected(edgeRouter *model.EdgeRouter, router *network.Router) {
	rtx := newRouterSender(edgeRouter, router, strategy.RouterTxBufferSize)
	rtx.Status = env.RouterSyncQueued

	log := pfxlog.Logger().WithField("sync_strategy", strategy.Type()).
		WithField("syncStatus", rtx.Status).
		WithField("routerId", rtx.Router.Id).
		WithField("routerName", rtx.Router.Name).
		WithField("routerFingerprint", rtx.Router.Fingerprint)

	log.Info("edge router connected, adding to sync routerConnectedQueue")

	strategy.rtxMap.Add(router.Id, rtx)

	strategy.routerConnectedQueue <- rtx
}

func (strategy *InstantStrategy) RouterDisconnected(router *network.Router) {
	strategy.rtxMap.Remove(router.Id)
}

func (strategy *InstantStrategy) ApiSessionAdded(apiSession *persistence.ApiSession) {
	logger := pfxlog.Logger().WithField("strategy", strategy.Type())

	apiSessionProto, err := apiSessionToProto(strategy.ae, apiSession.Token, apiSession.IdentityId, apiSession.Id)

	if err != nil {
		logger.WithField("apiSessionId", apiSession.Id).
			Errorf("error for individual api session added, could not convert to proto: %v", err)
		return
	}

	state := &InstantSyncState{
		Id:       cuid.New(),
		IsLast:   true,
		Sequence: 0,
	}

	strategy.rtxMap.Range(func(rtx *RouterSender) bool {
		strategy.sendApiSessionAdded(rtx, false, state, []*edge_ctrl_pb.ApiSession{apiSessionProto})
		return true
	})
}

func (strategy *InstantStrategy) ApiSessionUpdated(apiSession *persistence.ApiSession, _ *persistence.ApiSessionCertificate) {
	logger := pfxlog.Logger().WithField("strategy", strategy.Type())

	apiSessionProto, err := apiSessionToProto(strategy.ae, apiSession.Token, apiSession.IdentityId, apiSession.Id)

	if err != nil {
		logger.WithField("apiSessionId", apiSession.Id).
			Errorf("error for individual api session added, could not convert to proto: %v", err)
		return
	}

	apiSessionAdded := &edge_ctrl_pb.ApiSessionAdded{
		IsFullState: false,
		ApiSessions: []*edge_ctrl_pb.ApiSession{apiSessionProto},
	}

	strategy.rtxMap.Range(func(rtx *RouterSender) bool {
		content, _ := proto.Marshal(apiSessionAdded)
		msg := channel2.NewMessage(env.ApiSessionUpdatedType, content)
		msg.Headers[env.SyncStrategyTypeHeader] = []byte(strategy.Type())
		msg.Headers[env.SyncStrategyStateHeader] = nil
		rtx.Send(msg)
		return true
	})
}

func (strategy *InstantStrategy) ApiSessionDeleted(apiSession *persistence.ApiSession) {
	sessionRemoved := &edge_ctrl_pb.ApiSessionRemoved{
		Tokens: []string{apiSession.Token},
	}

	strategy.rtxMap.Range(func(rtx *RouterSender) bool {
		content, _ := proto.Marshal(sessionRemoved)
		msg := channel2.NewMessage(env.ApiSessionRemovedType, content)
		rtx.Send(msg)
		return true
	})
}

func (strategy *InstantStrategy) SessionAdded(session *persistence.Session) {
	logger := pfxlog.Logger().WithField("strategy", strategy.Type())

	sessionProto, err := sessionToProto(strategy.ae, session)

	if err != nil {
		logger.WithField("sessionId", session.Id).
			Errorf("error for individual session added, could not convert to proto: %v", err)
		return
	}

	state := &InstantSyncState{
		Id:       cuid.New(),
		IsLast:   true,
		Sequence: 0,
	}
	strategy.rtxMap.Range(func(rtx *RouterSender) bool {
		strategy.sendSessionAdded(rtx, false, state, []*edge_ctrl_pb.Session{sessionProto})
		return true
	})
}

func (strategy *InstantStrategy) SessionDeleted(session *persistence.Session) {
	sessionRemoved := &edge_ctrl_pb.SessionRemoved{
		Tokens: []string{session.Token},
	}

	strategy.rtxMap.Range(func(rtx *RouterSender) bool {
		content, _ := proto.Marshal(sessionRemoved)
		msg := channel2.NewMessage(env.SessionRemovedType, content)
		rtx.Send(msg)
		return true
	})
}

func (strategy *InstantStrategy) startHandleRouterConnectWorker() {
	select {
	case <-strategy.stop:
		return
	case rtx := <-strategy.routerConnectedQueue:
		strategy.hello(rtx)
	}
}

func (strategy *InstantStrategy) startSynchronizeWorker() {
	select {
	case <-strategy.stop:
		return
	case rtx := <-strategy.receivedClientHelloQueue:
		strategy.synchronize(rtx)
	}
}

func (strategy *InstantStrategy) hello(rtx *RouterSender) {
	logger := rtx.logger().WithField("strategy", strategy.Type())

	logger.Info("edge router sync starting")

	if rtx.Router.Control.IsClosed() {
		rtx.Status = env.RouterSyncDisconnected
		logger.WithField("syncStatus", rtx.Status).Info("edge router sync aborting, edge router disconnected before sync started")
		return
	}

	rtx.Router.Control.AddReceiveHandler(strategy.helloHandler)
	rtx.Status = env.RouterSyncHello
	logger.WithField("syncStatus", rtx.Status).Info("sending edge router hello")
	strategy.sendHello(rtx)
}

func (strategy *InstantStrategy) sendHello(rtx *RouterSender) {
	logger := rtx.logger().WithField("strategy", strategy.Type())
	serverVersion := build.GetBuildInfo().Version()
	serverHello := &edge_ctrl_pb.ServerHello{
		Version: serverVersion,
	}

	buf, err := proto.Marshal(serverHello)
	if err != nil {
		logger.WithError(err).Error("could not marshal serverHello")
		return
	}

	if err = rtx.Router.Control.SendWithTimeout(channel2.NewMessage(env.ServerHelloType, buf), strategy.HelloSendTimeout); err != nil {
		if rtx.Router.Control.IsClosed() {
			rtx.Status = env.RouterSyncDisconnected
			rtx.logger().WithError(err).Error("timed out sending serverHello message for edge router, connection closed, giving up")
		} else {
			rtx.Status = env.RouterSyncHelloTimeout
			rtx.logger().WithError(err).Error("timed out sending serverHello message for edge router, queuing again")
			go func() {
				strategy.routerConnectedQueue <- rtx
			}()
		}
	}
}

func (strategy *InstantStrategy) ReceiveResync(r *network.Router, hello *edge_ctrl_pb.RequestClientReSync) {
	rtx := strategy.rtxMap.Get(r.Id)

	if rtx == nil {
		pfxlog.Logger().
			WithField("strategy", strategy.Type()).
			WithField("routerId", r.Id).
			WithField("routerName", r.Name).
			Error("received resync from router that is currently not tracked by the strategy, dropping resync")
		return
	}

	rtx.Status = env.RouterSyncResyncWait

	rtx.logger().WithField("strategy", strategy.Type()).Info("received resync from router, queuing")

	strategy.receivedClientHelloQueue <- rtx
}

func (strategy *InstantStrategy) ReceiveClientHello(r *network.Router, respHello *edge_ctrl_pb.ClientHello) {

	rtx := strategy.rtxMap.Get(r.Id)

	if rtx == nil {
		pfxlog.Logger().
			WithField("strategy", strategy.Type()).
			WithField("routerId", r.Id).
			WithField("routerName", r.Name).
			Error("received hello from router that is currently not tracked by the strategy, dropping hello")
		return
	}

	rtx.Status = env.RouterSyncHelloWait

	logger := rtx.logger().WithField("strategy", strategy.Type()).
		WithField("hostname", respHello.Hostname).
		WithField("protocols", respHello.Protocols).
		WithField("protocolPorts", respHello.ProtocolPorts).
		WithField("data", respHello.Data)

	serverVersion := build.GetBuildInfo().Version()

	if r.VersionInfo != nil {
		logger = logger.WithField("version", r.VersionInfo.Version).
			WithField("revision", r.VersionInfo.Revision).
			WithField("buildDate", r.VersionInfo.BuildDate).
			WithField("os", r.VersionInfo.OS).
			WithField("arch", r.VersionInfo.Arch)
	}

	protocols := map[string]string{}
	for _, p := range respHello.ProtocolPorts {
		parts := strings.Split(p, ":")
		ingressUrl := fmt.Sprintf("%s://%s:%s", parts[0], respHello.Hostname, parts[1])
		protocols[parts[0]] = ingressUrl
	}

	rtx.EdgeRouter.Hostname = &respHello.Hostname
	rtx.EdgeRouter.EdgeRouterProtocols = protocols
	rtx.EdgeRouter.VersionInfo = r.VersionInfo

	logger.Infof("edge router sent hello with version [%s] to controller with version [%s]", respHello.Version, serverVersion)
	strategy.receivedClientHelloQueue <- rtx
}

func (strategy *InstantStrategy) synchronize(rtx *RouterSender) {
	defer func() {
		rtx.logger().WithField("strategy", strategy.Type()).Infof("exiting synchronization, final status: %s", rtx.Status)
	}()

	if rtx.Router.Control.IsClosed() {
		rtx.Status = env.RouterSyncDisconnected
		rtx.logger().WithField("strategy", strategy.Type()).Error("attempting to start synchronization with edge router, but it has disconnected")
	}

	rtx.Status = env.RouterSynInProgress
	logger := rtx.logger().WithField("strategy", strategy.Type())
	logger.Info("started synchronizing edge router")

	chunkSize := 100
	strategy.ae.GetDbProvider().GetDb().View(func(tx *bbolt.Tx) error {
		var apiSessions []*edge_ctrl_pb.ApiSession

		state := &InstantSyncState{
			Id:       cuid.New(),
			IsLast:   true,
			Sequence: 0,
		}

		for cursor := strategy.ae.GetStores().ApiSession.IterateIds(tx, ast.BoolNodeTrue); cursor.IsValid(); cursor.Next() {
			current := cursor.Current()

			apiSession, err := strategy.ae.GetStores().ApiSession.LoadOneById(tx, string(current))

			if err != nil {
				logger.WithError(err).WithField("apiSessionId", string(current)).Errorf("error querying api session [%s]: %v", string(current), err)
				continue
			}

			apiSessionProto, err := apiSessionToProto(strategy.ae, apiSession.Token, apiSession.IdentityId, apiSession.Id)

			if err != nil {
				logger.WithError(err).WithField("apiSessionId", string(current)).Errorf("error turning apiSession [%s] into proto: %v", string(current), err)
				continue
			}

			apiSessions = append(apiSessions, apiSessionProto)

			if len(apiSessions) >= chunkSize {
				state.IsLast = !cursor.IsValid()
				strategy.sendApiSessionAdded(rtx, true, state, apiSessions)

				state.Sequence = state.Sequence + 1
				apiSessions = []*edge_ctrl_pb.ApiSession{}
			}
		}

		if len(apiSessions) > 0 {
			state.IsLast = true
			strategy.sendApiSessionAdded(rtx, true, state, apiSessions)
		}
		return nil
	})

	strategy.ae.GetDbProvider().GetDb().View(func(tx *bbolt.Tx) error {
		var sessions []*edge_ctrl_pb.Session

		state := &InstantSyncState{
			Id:       cuid.New(),
			IsLast:   true,
			Sequence: 0,
		}

		for cursor := strategy.ae.GetStores().Session.IterateIds(tx, ast.BoolNodeTrue); cursor.IsValid(); cursor.Next() {
			current := cursor.Current()

			session, err := strategy.ae.GetStores().Session.LoadOneById(tx, string(current))

			if err != nil {
				logger.WithError(err).WithField("sessionId", string(current)).Errorf("error querying session [%s]: %v", string(current), err)
				continue
			}

			sessionProto, err := sessionToProto(strategy.ae, session)

			if err != nil {
				logger.WithError(err).WithField("sessionId", string(current)).Errorf("error turning session [%s] into proto: %v", string(current), err)
				continue
			}

			sessions = append(sessions, sessionProto)

			if len(sessions) >= chunkSize {
				state.IsLast = !cursor.IsValid()
				strategy.sendSessionAdded(rtx, true, state, sessions)

				state.Sequence = state.Sequence + 1
				sessions = []*edge_ctrl_pb.Session{}
			}
		}

		if len(sessions) > 0 {
			state.IsLast = true
			strategy.sendSessionAdded(rtx, true, state, sessions)
		}
		return nil
	})

	rtx.Status = env.RouterSyncDone
}

func (strategy *InstantStrategy) sendApiSessionAdded(rtx *RouterSender, isFullState bool, state *InstantSyncState, apiSessions []*edge_ctrl_pb.ApiSession) {
	stateBytes, _ := json.Marshal(state)

	msgContent := &edge_ctrl_pb.ApiSessionAdded{
		IsFullState: isFullState,
		ApiSessions: apiSessions,
	}

	msgContentBytes, _ := proto.Marshal(msgContent)

	msg := channel2.NewMessage(env.ApiSessionAddedType, msgContentBytes)

	msg.Headers[env.SyncStrategyTypeHeader] = []byte(strategy.Type())
	msg.Headers[env.SyncStrategyStateHeader] = stateBytes

	rtx.Send(msg)
}

func (strategy *InstantStrategy) sendSessionAdded(rtx *RouterSender, isFullState bool, state *InstantSyncState, sessions []*edge_ctrl_pb.Session) {

	stateBytes, _ := json.Marshal(state)

	msgContent := &edge_ctrl_pb.SessionAdded{
		IsFullState: isFullState,
		Sessions:    sessions,
	}

	msgContentBytes, _ := proto.Marshal(msgContent)

	msg := channel2.NewMessage(env.SessionAddedType, msgContentBytes)
	msg.Headers[env.SyncStrategyTypeHeader] = []byte(strategy.Type())
	msg.Headers[env.SyncStrategyStateHeader] = stateBytes
	rtx.Send(msg)
}

type InstantSyncState struct {
	Id       string `json:"id"`       //unique id for the sync attempt
	IsLast   bool   `json:"isLast"`   //
	Sequence int    `json:"sequence"` //inreasing id from 0 per id for the
}
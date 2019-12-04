package xgress_edge_wss

import (
	"errors"
	"fmt"
	"github.com/michaelquigley/pfxlog"
	"github.com/netfoundry/ziti-edge/edge/gateway/internal/fabric"
	"github.com/netfoundry/ziti-edge/edge/internal/cert"
	"github.com/netfoundry/ziti-edge/edge/pb/edge_ctrl_pb"
	"github.com/netfoundry/ziti-edge/sdk/ziti/edge"
	"github.com/netfoundry/ziti-foundation/channel2"
	"time"
)

type sessionConnectionHandler struct {
	stateManager fabric.StateManager
}

func newSessionConnectHandler(stateManager fabric.StateManager) *sessionConnectionHandler {
	return &sessionConnectionHandler{stateManager: stateManager}
}

func (handler *sessionConnectionHandler) BindChannel(ch channel2.Channel) error {
	ch.AddCloseHandler(handler)

	if byteToken, ok := ch.Underlay().Headers()[edge.SessionTokenHeader]; ok {
		token := string(byteToken)

		certificates := ch.Certificates()

		if len(certificates) == 0 {
			return errors.New("no client certificates provided")
		}

		fpg := cert.NewFingerprintGenerator()
		fingerprints := fpg.FromCerts(certificates)

		sessionCh := handler.stateManager.GetSession(token)
		var session *edge_ctrl_pb.ApiSession
		select {
		case session = <-sessionCh:
		case <-time.After(250 * time.Millisecond):
			return errors.New("session token lookup timeout")
		}

		if session == nil {
			return fmt.Errorf("no session found")
		}

		for _, fingerprint := range session.CertFingerprints {
			if fingerprints.Contains(fingerprint) {
				removeListener := handler.stateManager.AddSessionRemovedListener(token, func(token string) {
					if !ch.IsClosed() {
						err := ch.Close()

						if err != nil {
							pfxlog.Logger().WithError(err).Error("could not close channel during session removal")
						}
					}
				})

				handler.stateManager.AddConnectedSession(token, removeListener, ch)

				return nil
			}
		}

		return errors.New("invalid client certificate for session")
	}
	return errors.New("no token attribute provided")
}

func (handler *sessionConnectionHandler) HandleClose(ch channel2.Channel) {
	token := ""
	if byteToken, ok := ch.Underlay().Headers()[edge.SessionTokenHeader]; ok {
		token = string(byteToken)

		handler.stateManager.RemoveConnectedSession(token, ch)
	} else {
		pfxlog.Logger().
			WithField("id", ch.Id()).
			Error("session connection handler encountered a HandleClose that did not have a SessionTokenHeader")
	}

}

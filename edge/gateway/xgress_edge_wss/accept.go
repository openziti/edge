package xgress_edge_wss

import (
	"github.com/netfoundry/ziti-foundation/channel2"
	// "github.com/netfoundry/ziti-edge/edge/gateway/internal/fabric"
	"github.com/michaelquigley/pfxlog"
	"github.com/netfoundry/ziti-edge/edge/internal/cert"
	"github.com/netfoundry/ziti-edge/sdk/ziti/edge"
)

type Accepter struct {
	uListener channel2.UnderlayListener
	listener  *listener
	options   *channel2.Options
}

type edgeBindHandler struct {
	listener *listener
}

func (handler edgeBindHandler) BindChannel(ch channel2.Channel) error {
	log := pfxlog.Logger()
	log.WithField("token", ch.Id()).Info("accepting edge_wss connection")

	fpg := cert.NewFingerprintGenerator()
	proxy := &ingressProxy{
		msgMux:       edge.NewMsgMux(),
		listener:     handler.listener,
		fingerprints: fpg.FromCerts(ch.Certificates()),
		ch:           ch,
	}

	log.Debug("peer fingerprints ", proxy.fingerprints)

	ch.AddReceiveHandler(&edge.FunctionReceiveAdapter{
		Type:    edge.ContentTypeConnect,
		Handler: proxy.processConnect,
	})

	ch.AddReceiveHandler(&edge.FunctionReceiveAdapter{
		Type:    edge.ContentTypeBind,
		Handler: proxy.processBind,
	})

	ch.AddReceiveHandler(&edge.FunctionReceiveAdapter{
		Type:    edge.ContentTypeUnbind,
		Handler: proxy.processUnbind,
	})

	ch.AddReceiveHandler(&edge.FunctionReceiveAdapter{
		Type:    edge.ContentTypeStateClosed,
		Handler: proxy.msgMux.HandleReceive,
	})

	// Since data is most common type, it gets to dispatch directly
	ch.AddReceiveHandler(proxy.msgMux)
	ch.AddCloseHandler(proxy)

	return nil
}

func NewAccepter(listener *listener, uListener channel2.UnderlayListener, options *channel2.Options) *Accepter {
	edgeBindHandler := &edgeBindHandler{listener: listener}
	// sessionHandler := newSessionConnectHandler(fabric.GetStateManager())

	optionsWithBind := options
	if optionsWithBind == nil {
		optionsWithBind = channel2.DefaultOptions()
	}

	// optionsWithBind.BindHandlers = append(optionsWithBind.BindHandlers, edgeBindHandler, sessionHandler)
	optionsWithBind.BindHandlers = append(optionsWithBind.BindHandlers, edgeBindHandler)

	return &Accepter{
		listener:  listener,
		uListener: uListener,
		options:   optionsWithBind,
	}
}

func (accepter *Accepter) Run() {
	log := pfxlog.Logger()
	log.Info("starting")
	defer log.Warn("exiting")

	for {
		if _, err := channel2.NewChannel("edge_wss", accepter.uListener, accepter.options); err != nil {
			log.Errorf("error accepting (%s)", err)
		}
	}

}

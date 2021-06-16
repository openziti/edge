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

package routes

import (
	"context"
	health "github.com/AppsFlyer/go-sundheit"
	"github.com/AppsFlyer/go-sundheit/checks"
	"github.com/go-openapi/runtime/middleware"
	"github.com/openziti/edge/controller/env"
	"github.com/openziti/edge/controller/internal/permissions"
	"github.com/openziti/edge/controller/response"
	"github.com/openziti/edge/rest_management_api_server/operations/informational"
	"github.com/openziti/foundation/metrics"
	"github.com/openziti/foundation/util/concurrenz"
	"github.com/openziti/sdk-golang/ziti/edge/impl"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"go.etcd.io/bbolt"
	"time"
)

func init() {
	r := NewHealthCheckRouter()
	env.AddRouter(r)
}

type HealthCheckRouter struct {
	BasePath      string
	healthChecker health.Health
}

func NewHealthCheckRouter() *HealthCheckRouter {
	return &HealthCheckRouter{
		BasePath:      "/health-check",
		healthChecker: health.New(),
	}
}

func (r *HealthCheckRouter) Register(ae *env.AppEnv) {
	ae.ManagementApi.InformationalHealthCheckHandler = informational.HealthCheckHandlerFunc(func(params informational.HealthCheckParams) middleware.Responder {
		return ae.IsAllowed(r.HealthCheck, params.HTTPRequest, "", "", permissions.Always())
	})

	check, err := checks.NewPingCheck("bolt.read", &boltPinger{
		appEnv:      ae,
		openReadTxs: ae.GetMetricsRegistry().Gauge("bolt.open_read_txs"),
	})

	if err != nil {
		logrus.WithError(err).Fatal("unable to create bolt.read ping check")
		return
	}

	// TODO: once we have fabric xweb based API, move this to fabric and make check configurable
	err = r.healthChecker.RegisterCheck(check, health.ExecutionPeriod(30*time.Second), health.InitiallyPassing(true), health.ExecutionTimeout(15*time.Second))
	if err != nil {
		logrus.WithError(err).Fatal("unable to register bolt.read ping check")
		return
	}
}

func (r *HealthCheckRouter) HealthCheck(ae *env.AppEnv, rc *response.RequestContext) {
	results, healthy := r.healthChecker.Results()
	if healthy {
		rc.RespondWithEmptyOk()
		return
	}

	var errs []error

	for id, result := range results {
		if !result.IsHealthy() {
			if result.Error != nil {
				errs = append(errs, result.Error)
			} else {
				errs = append(errs, errors.Errorf("check %v reports unhealthy state", id))
			}
		}
	}

	if len(errs) == 1 {
		rc.RespondWithError(errs[0])
	} else {
		rc.RespondWithError(impl.MultipleErrors(errs))
	}
}

type boltPinger struct {
	appEnv      *env.AppEnv
	openReadTxs metrics.Gauge
	running     concurrenz.AtomicBoolean
}

func (self *boltPinger) PingContext(ctx context.Context) error {
	if !self.running.CompareAndSwap(false, true) {
		return errors.Errorf("previous bolt ping is still running")
	}

	deadline, hasDeadline := ctx.Deadline()

	checkFunc := func(tx *bbolt.Tx) error {
		self.openReadTxs.Update(int64(tx.DB().Stats().OpenTxN))
		return nil
	}

	if !hasDeadline {
		defer self.running.Set(false)
		return self.appEnv.GetDbProvider().GetDb().View(checkFunc)
	}

	errC := make(chan error, 1)
	go func() {
		defer self.running.Set(false)
		errC <- self.appEnv.GetDbProvider().GetDb().View(checkFunc)
	}()

	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()

	select {
	case err := <-errC:
		return err
	case <-timer.C:
		return errors.Errorf("bolt ping timed out")
	}
}

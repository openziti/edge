/*
	Copyright 2020 NetFoundry, Inc.

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
	"github.com/netfoundry/ziti-edge/controller/env"
	"github.com/netfoundry/ziti-edge/controller/internal/permissions"
	"github.com/netfoundry/ziti-edge/controller/response"
)

func init() {
	r := NewEndpointRouter()
	env.AddRouter(r)
}

type EndpointRouter struct {
	BasePath string
	IdType   response.IdType
}

func NewEndpointRouter() *EndpointRouter {
	return &EndpointRouter{
		BasePath: "/" + EntityNameEndpoint,
		IdType:   response.IdTypeUuid,
	}
}

func (ir *EndpointRouter) Register(ae *env.AppEnv) {
	registerCrudRouter(ae, ae.RootRouter, ir.BasePath, ir, permissions.IsAdmin())
}

func (ir *EndpointRouter) List(ae *env.AppEnv, rc *response.RequestContext) {
	// ListWithHandler(ae, rc, ae.Handlers.Endpoint, MapEndpointToApiEntity)
}

func (ir *EndpointRouter) Detail(ae *env.AppEnv, rc *response.RequestContext) {
	DetailWithHandler(ae, rc, ae.Handlers.Endpoint, MapEndpointToApiEntity, ir.IdType)
}

func (ir *EndpointRouter) Create(ae *env.AppEnv, rc *response.RequestContext) {
	apiEntity := &EndpointApi{}
	Create(rc, rc.RequestResponder, ae.Schemes.Endpoint.Post, apiEntity, (&EndpointApiList{}).BuildSelfLink, func() (string, error) {
		return ae.Handlers.Endpoint.Create(apiEntity.ToModel(""))
	})
}

func (ir *EndpointRouter) Delete(ae *env.AppEnv, rc *response.RequestContext) {
	DeleteWithHandler(rc, ir.IdType, ae.Handlers.Endpoint)
}

func (ir *EndpointRouter) Update(ae *env.AppEnv, rc *response.RequestContext) {
	apiEntity := &EndpointApi{}
	Update(rc, ae.Schemes.Endpoint.Put, ir.IdType, apiEntity, func(id string) error {
		return ae.Handlers.Endpoint.Update(apiEntity.ToModel(id))
	})
}

func (ir *EndpointRouter) Patch(ae *env.AppEnv, rc *response.RequestContext) {
	apiEntity := &EndpointApi{}
	Patch(rc, ae.Schemes.Endpoint.Patch, ir.IdType, apiEntity, func(id string, fields JsonFields) error {
		return ae.Handlers.Endpoint.Patch(apiEntity.ToModel(id), fields.FilterMaps("tags"))
	})
}

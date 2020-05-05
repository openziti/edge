// Code generated by go-swagger; DO NOT EDIT.

//
// Copyright NetFoundry, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// __          __              _
// \ \        / /             (_)
//  \ \  /\  / /_ _ _ __ _ __  _ _ __   __ _
//   \ \/  \/ / _` | '__| '_ \| | '_ \ / _` |
//    \  /\  / (_| | |  | | | | | | | | (_| | : This file is generated, do not edit it.
//     \/  \/ \__,_|_|  |_| |_|_|_| |_|\__, |
//                                      __/ |
//                                     |___/

package certificate_authority

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"net/http"

	"github.com/go-openapi/runtime/middleware"
)

// GetCaJwtHandlerFunc turns a function with the right signature into a get ca jwt handler
type GetCaJwtHandlerFunc func(GetCaJwtParams, interface{}) middleware.Responder

// Handle executing the request and returning a response
func (fn GetCaJwtHandlerFunc) Handle(params GetCaJwtParams, principal interface{}) middleware.Responder {
	return fn(params, principal)
}

// GetCaJwtHandler interface for that can handle valid get ca jwt params
type GetCaJwtHandler interface {
	Handle(GetCaJwtParams, interface{}) middleware.Responder
}

// NewGetCaJwt creates a new http.Handler for the get ca jwt operation
func NewGetCaJwt(ctx *middleware.Context, handler GetCaJwtHandler) *GetCaJwt {
	return &GetCaJwt{Context: ctx, Handler: handler}
}

/*GetCaJwt swagger:route GET /cas/{id}/jwt Certificate Authority getCaJwt

Retrieve the enrollment JWT for a CA

For CA auto enrollment, the enrollment JWT is static and provided on each CA resource. This endpoint provides
the jwt as a text response.


*/
type GetCaJwt struct {
	Context *middleware.Context
	Handler GetCaJwtHandler
}

func (o *GetCaJwt) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		r = rCtx
	}
	var Params = NewGetCaJwtParams()

	uprinc, aCtx, err := o.Context.Authorize(r, route)
	if err != nil {
		o.Context.Respond(rw, r, route.Produces, route, err)
		return
	}
	if aCtx != nil {
		r = aCtx
	}
	var principal interface{}
	if uprinc != nil {
		principal = uprinc
	}

	if err := o.Context.BindValidRequest(r, route, &Params); err != nil { // bind params
		o.Context.Respond(rw, r, route.Produces, route, err)
		return
	}

	res := o.Handler.Handle(Params, principal) // actually handle the request

	o.Context.Respond(rw, r, route.Produces, route, res)

}

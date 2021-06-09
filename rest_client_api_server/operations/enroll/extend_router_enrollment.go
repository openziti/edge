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

package enroll

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"net/http"

	"github.com/go-openapi/runtime/middleware"
)

// ExtendRouterEnrollmentHandlerFunc turns a function with the right signature into a extend router enrollment handler
type ExtendRouterEnrollmentHandlerFunc func(ExtendRouterEnrollmentParams) middleware.Responder

// Handle executing the request and returning a response
func (fn ExtendRouterEnrollmentHandlerFunc) Handle(params ExtendRouterEnrollmentParams) middleware.Responder {
	return fn(params)
}

// ExtendRouterEnrollmentHandler interface for that can handle valid extend router enrollment params
type ExtendRouterEnrollmentHandler interface {
	Handle(ExtendRouterEnrollmentParams) middleware.Responder
}

// NewExtendRouterEnrollment creates a new http.Handler for the extend router enrollment operation
func NewExtendRouterEnrollment(ctx *middleware.Context, handler ExtendRouterEnrollmentHandler) *ExtendRouterEnrollment {
	return &ExtendRouterEnrollment{Context: ctx, Handler: handler}
}

/* ExtendRouterEnrollment swagger:route POST /enroll/extend/router Enroll Extend Enrollment extendRouterEnrollment

Extend the life of a currently enrolled router's certificates

Allows a router to extend its certificates' expiration date by
using its current and valid client certificate to submit a CSR. This CSR may
be pased in using a new private key, thus allowing private key rotation or swapping.

After completion any new connections must be made with certificates returned from a 200 OK
response. Previous client certificate is rendered invalid for use with the controller even if it
has not expired.

This request must be made using the existing, valid, client certificate.


*/
type ExtendRouterEnrollment struct {
	Context *middleware.Context
	Handler ExtendRouterEnrollmentHandler
}

func (o *ExtendRouterEnrollment) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		*r = *rCtx
	}
	var Params = NewExtendRouterEnrollmentParams()
	if err := o.Context.BindValidRequest(r, route, &Params); err != nil { // bind params
		o.Context.Respond(rw, r, route.Produces, route, err)
		return
	}

	res := o.Handler.Handle(Params) // actually handle the request
	o.Context.Respond(rw, r, route.Produces, route, res)

}
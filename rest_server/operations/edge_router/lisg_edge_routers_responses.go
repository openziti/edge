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

package edge_router

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	"github.com/netfoundry/ziti-edge/models"
)

// LisgEdgeRoutersOKCode is the HTTP code returned for type LisgEdgeRoutersOK
const LisgEdgeRoutersOKCode int = 200

/*LisgEdgeRoutersOK A list of edge routers

swagger:response lisgEdgeRoutersOK
*/
type LisgEdgeRoutersOK struct {

	/*
	  In: Body
	*/
	Payload *models.ListEdgeRoutersEnvelope `json:"body,omitempty"`
}

// NewLisgEdgeRoutersOK creates LisgEdgeRoutersOK with default headers values
func NewLisgEdgeRoutersOK() *LisgEdgeRoutersOK {

	return &LisgEdgeRoutersOK{}
}

// WithPayload adds the payload to the lisg edge routers o k response
func (o *LisgEdgeRoutersOK) WithPayload(payload *models.ListEdgeRoutersEnvelope) *LisgEdgeRoutersOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the lisg edge routers o k response
func (o *LisgEdgeRoutersOK) SetPayload(payload *models.ListEdgeRoutersEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *LisgEdgeRoutersOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// LisgEdgeRoutersUnauthorizedCode is the HTTP code returned for type LisgEdgeRoutersUnauthorized
const LisgEdgeRoutersUnauthorizedCode int = 401

/*LisgEdgeRoutersUnauthorized The currently supplied session does not have the correct access rights to request this resource

swagger:response lisgEdgeRoutersUnauthorized
*/
type LisgEdgeRoutersUnauthorized struct {

	/*
	  In: Body
	*/
	Payload *models.APIErrorEnvelope `json:"body,omitempty"`
}

// NewLisgEdgeRoutersUnauthorized creates LisgEdgeRoutersUnauthorized with default headers values
func NewLisgEdgeRoutersUnauthorized() *LisgEdgeRoutersUnauthorized {

	return &LisgEdgeRoutersUnauthorized{}
}

// WithPayload adds the payload to the lisg edge routers unauthorized response
func (o *LisgEdgeRoutersUnauthorized) WithPayload(payload *models.APIErrorEnvelope) *LisgEdgeRoutersUnauthorized {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the lisg edge routers unauthorized response
func (o *LisgEdgeRoutersUnauthorized) SetPayload(payload *models.APIErrorEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *LisgEdgeRoutersUnauthorized) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(401)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

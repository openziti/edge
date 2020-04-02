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

package service_edge_router_policy

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	"github.com/netfoundry/ziti-edge/models"
)

// CreateServiceEdgeRouterPolicyOKCode is the HTTP code returned for type CreateServiceEdgeRouterPolicyOK
const CreateServiceEdgeRouterPolicyOKCode int = 200

/*CreateServiceEdgeRouterPolicyOK The create request was successful and the resource has been added at the following location

swagger:response createServiceEdgeRouterPolicyOK
*/
type CreateServiceEdgeRouterPolicyOK struct {

	/*
	  In: Body
	*/
	Payload *models.Create `json:"body,omitempty"`
}

// NewCreateServiceEdgeRouterPolicyOK creates CreateServiceEdgeRouterPolicyOK with default headers values
func NewCreateServiceEdgeRouterPolicyOK() *CreateServiceEdgeRouterPolicyOK {

	return &CreateServiceEdgeRouterPolicyOK{}
}

// WithPayload adds the payload to the create service edge router policy o k response
func (o *CreateServiceEdgeRouterPolicyOK) WithPayload(payload *models.Create) *CreateServiceEdgeRouterPolicyOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the create service edge router policy o k response
func (o *CreateServiceEdgeRouterPolicyOK) SetPayload(payload *models.Create) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *CreateServiceEdgeRouterPolicyOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// CreateServiceEdgeRouterPolicyBadRequestCode is the HTTP code returned for type CreateServiceEdgeRouterPolicyBadRequest
const CreateServiceEdgeRouterPolicyBadRequestCode int = 400

/*CreateServiceEdgeRouterPolicyBadRequest The supplied request contains invalid fields or could not be parsed (json and non-json bodies). The error's code, message, and cause fields can be inspected for further information

swagger:response createServiceEdgeRouterPolicyBadRequest
*/
type CreateServiceEdgeRouterPolicyBadRequest struct {

	/*
	  In: Body
	*/
	Payload *models.APIErrorEnvelope `json:"body,omitempty"`
}

// NewCreateServiceEdgeRouterPolicyBadRequest creates CreateServiceEdgeRouterPolicyBadRequest with default headers values
func NewCreateServiceEdgeRouterPolicyBadRequest() *CreateServiceEdgeRouterPolicyBadRequest {

	return &CreateServiceEdgeRouterPolicyBadRequest{}
}

// WithPayload adds the payload to the create service edge router policy bad request response
func (o *CreateServiceEdgeRouterPolicyBadRequest) WithPayload(payload *models.APIErrorEnvelope) *CreateServiceEdgeRouterPolicyBadRequest {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the create service edge router policy bad request response
func (o *CreateServiceEdgeRouterPolicyBadRequest) SetPayload(payload *models.APIErrorEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *CreateServiceEdgeRouterPolicyBadRequest) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(400)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// CreateServiceEdgeRouterPolicyUnauthorizedCode is the HTTP code returned for type CreateServiceEdgeRouterPolicyUnauthorized
const CreateServiceEdgeRouterPolicyUnauthorizedCode int = 401

/*CreateServiceEdgeRouterPolicyUnauthorized The currently supplied session does not have the correct access rights to request this resource

swagger:response createServiceEdgeRouterPolicyUnauthorized
*/
type CreateServiceEdgeRouterPolicyUnauthorized struct {

	/*
	  In: Body
	*/
	Payload *models.APIErrorEnvelope `json:"body,omitempty"`
}

// NewCreateServiceEdgeRouterPolicyUnauthorized creates CreateServiceEdgeRouterPolicyUnauthorized with default headers values
func NewCreateServiceEdgeRouterPolicyUnauthorized() *CreateServiceEdgeRouterPolicyUnauthorized {

	return &CreateServiceEdgeRouterPolicyUnauthorized{}
}

// WithPayload adds the payload to the create service edge router policy unauthorized response
func (o *CreateServiceEdgeRouterPolicyUnauthorized) WithPayload(payload *models.APIErrorEnvelope) *CreateServiceEdgeRouterPolicyUnauthorized {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the create service edge router policy unauthorized response
func (o *CreateServiceEdgeRouterPolicyUnauthorized) SetPayload(payload *models.APIErrorEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *CreateServiceEdgeRouterPolicyUnauthorized) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(401)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

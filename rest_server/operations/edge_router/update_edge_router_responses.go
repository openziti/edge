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

	"github.com/netfoundry/ziti-edge/rest_model"
)

// UpdateEdgeRouterOKCode is the HTTP code returned for type UpdateEdgeRouterOK
const UpdateEdgeRouterOKCode int = 200

/*UpdateEdgeRouterOK The update request was successful and the resource has been altered

swagger:response updateEdgeRouterOK
*/
type UpdateEdgeRouterOK struct {

	/*
	  In: Body
	*/
	Payload *rest_model.Empty `json:"body,omitempty"`
}

// NewUpdateEdgeRouterOK creates UpdateEdgeRouterOK with default headers values
func NewUpdateEdgeRouterOK() *UpdateEdgeRouterOK {

	return &UpdateEdgeRouterOK{}
}

// WithPayload adds the payload to the update edge router o k response
func (o *UpdateEdgeRouterOK) WithPayload(payload *rest_model.Empty) *UpdateEdgeRouterOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the update edge router o k response
func (o *UpdateEdgeRouterOK) SetPayload(payload *rest_model.Empty) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *UpdateEdgeRouterOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// UpdateEdgeRouterBadRequestCode is the HTTP code returned for type UpdateEdgeRouterBadRequest
const UpdateEdgeRouterBadRequestCode int = 400

/*UpdateEdgeRouterBadRequest The supplied request contains invalid fields or could not be parsed (json and non-json bodies). The error's code, message, and cause fields can be inspected for further information

swagger:response updateEdgeRouterBadRequest
*/
type UpdateEdgeRouterBadRequest struct {

	/*
	  In: Body
	*/
	Payload *rest_model.APIErrorEnvelope `json:"body,omitempty"`
}

// NewUpdateEdgeRouterBadRequest creates UpdateEdgeRouterBadRequest with default headers values
func NewUpdateEdgeRouterBadRequest() *UpdateEdgeRouterBadRequest {

	return &UpdateEdgeRouterBadRequest{}
}

// WithPayload adds the payload to the update edge router bad request response
func (o *UpdateEdgeRouterBadRequest) WithPayload(payload *rest_model.APIErrorEnvelope) *UpdateEdgeRouterBadRequest {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the update edge router bad request response
func (o *UpdateEdgeRouterBadRequest) SetPayload(payload *rest_model.APIErrorEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *UpdateEdgeRouterBadRequest) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(400)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// UpdateEdgeRouterUnauthorizedCode is the HTTP code returned for type UpdateEdgeRouterUnauthorized
const UpdateEdgeRouterUnauthorizedCode int = 401

/*UpdateEdgeRouterUnauthorized The currently supplied session does not have the correct access rights to request this resource

swagger:response updateEdgeRouterUnauthorized
*/
type UpdateEdgeRouterUnauthorized struct {

	/*
	  In: Body
	*/
	Payload *rest_model.APIErrorEnvelope `json:"body,omitempty"`
}

// NewUpdateEdgeRouterUnauthorized creates UpdateEdgeRouterUnauthorized with default headers values
func NewUpdateEdgeRouterUnauthorized() *UpdateEdgeRouterUnauthorized {

	return &UpdateEdgeRouterUnauthorized{}
}

// WithPayload adds the payload to the update edge router unauthorized response
func (o *UpdateEdgeRouterUnauthorized) WithPayload(payload *rest_model.APIErrorEnvelope) *UpdateEdgeRouterUnauthorized {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the update edge router unauthorized response
func (o *UpdateEdgeRouterUnauthorized) SetPayload(payload *rest_model.APIErrorEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *UpdateEdgeRouterUnauthorized) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(401)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// UpdateEdgeRouterNotFoundCode is the HTTP code returned for type UpdateEdgeRouterNotFound
const UpdateEdgeRouterNotFoundCode int = 404

/*UpdateEdgeRouterNotFound The requested resource does not exist

swagger:response updateEdgeRouterNotFound
*/
type UpdateEdgeRouterNotFound struct {

	/*
	  In: Body
	*/
	Payload *rest_model.APIErrorEnvelope `json:"body,omitempty"`
}

// NewUpdateEdgeRouterNotFound creates UpdateEdgeRouterNotFound with default headers values
func NewUpdateEdgeRouterNotFound() *UpdateEdgeRouterNotFound {

	return &UpdateEdgeRouterNotFound{}
}

// WithPayload adds the payload to the update edge router not found response
func (o *UpdateEdgeRouterNotFound) WithPayload(payload *rest_model.APIErrorEnvelope) *UpdateEdgeRouterNotFound {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the update edge router not found response
func (o *UpdateEdgeRouterNotFound) SetPayload(payload *rest_model.APIErrorEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *UpdateEdgeRouterNotFound) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(404)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

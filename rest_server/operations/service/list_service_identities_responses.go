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

package service

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	"github.com/netfoundry/ziti-edge/rest_model"
)

// ListServiceIdentitiesOKCode is the HTTP code returned for type ListServiceIdentitiesOK
const ListServiceIdentitiesOKCode int = 200

/*ListServiceIdentitiesOK A list of identities

swagger:response listServiceIdentitiesOK
*/
type ListServiceIdentitiesOK struct {

	/*
	  In: Body
	*/
	Payload *rest_model.ListIdentitiesEnvelope `json:"body,omitempty"`
}

// NewListServiceIdentitiesOK creates ListServiceIdentitiesOK with default headers values
func NewListServiceIdentitiesOK() *ListServiceIdentitiesOK {

	return &ListServiceIdentitiesOK{}
}

// WithPayload adds the payload to the list service identities o k response
func (o *ListServiceIdentitiesOK) WithPayload(payload *rest_model.ListIdentitiesEnvelope) *ListServiceIdentitiesOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the list service identities o k response
func (o *ListServiceIdentitiesOK) SetPayload(payload *rest_model.ListIdentitiesEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *ListServiceIdentitiesOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// ListServiceIdentitiesUnauthorizedCode is the HTTP code returned for type ListServiceIdentitiesUnauthorized
const ListServiceIdentitiesUnauthorizedCode int = 401

/*ListServiceIdentitiesUnauthorized The currently supplied session does not have the correct access rights to request this resource

swagger:response listServiceIdentitiesUnauthorized
*/
type ListServiceIdentitiesUnauthorized struct {

	/*
	  In: Body
	*/
	Payload *rest_model.APIErrorEnvelope `json:"body,omitempty"`
}

// NewListServiceIdentitiesUnauthorized creates ListServiceIdentitiesUnauthorized with default headers values
func NewListServiceIdentitiesUnauthorized() *ListServiceIdentitiesUnauthorized {

	return &ListServiceIdentitiesUnauthorized{}
}

// WithPayload adds the payload to the list service identities unauthorized response
func (o *ListServiceIdentitiesUnauthorized) WithPayload(payload *rest_model.APIErrorEnvelope) *ListServiceIdentitiesUnauthorized {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the list service identities unauthorized response
func (o *ListServiceIdentitiesUnauthorized) SetPayload(payload *rest_model.APIErrorEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *ListServiceIdentitiesUnauthorized) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(401)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

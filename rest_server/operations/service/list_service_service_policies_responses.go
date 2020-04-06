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

// ListServiceServicePoliciesOKCode is the HTTP code returned for type ListServiceServicePoliciesOK
const ListServiceServicePoliciesOKCode int = 200

/*ListServiceServicePoliciesOK A list of service policies

swagger:response listServiceServicePoliciesOK
*/
type ListServiceServicePoliciesOK struct {

	/*
	  In: Body
	*/
	Payload *rest_model.ListServicePoliciesEnvelope `json:"body,omitempty"`
}

// NewListServiceServicePoliciesOK creates ListServiceServicePoliciesOK with default headers values
func NewListServiceServicePoliciesOK() *ListServiceServicePoliciesOK {

	return &ListServiceServicePoliciesOK{}
}

// WithPayload adds the payload to the list service service policies o k response
func (o *ListServiceServicePoliciesOK) WithPayload(payload *rest_model.ListServicePoliciesEnvelope) *ListServiceServicePoliciesOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the list service service policies o k response
func (o *ListServiceServicePoliciesOK) SetPayload(payload *rest_model.ListServicePoliciesEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *ListServiceServicePoliciesOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// ListServiceServicePoliciesUnauthorizedCode is the HTTP code returned for type ListServiceServicePoliciesUnauthorized
const ListServiceServicePoliciesUnauthorizedCode int = 401

/*ListServiceServicePoliciesUnauthorized The currently supplied session does not have the correct access rights to request this resource

swagger:response listServiceServicePoliciesUnauthorized
*/
type ListServiceServicePoliciesUnauthorized struct {

	/*
	  In: Body
	*/
	Payload *rest_model.APIErrorEnvelope `json:"body,omitempty"`
}

// NewListServiceServicePoliciesUnauthorized creates ListServiceServicePoliciesUnauthorized with default headers values
func NewListServiceServicePoliciesUnauthorized() *ListServiceServicePoliciesUnauthorized {

	return &ListServiceServicePoliciesUnauthorized{}
}

// WithPayload adds the payload to the list service service policies unauthorized response
func (o *ListServiceServicePoliciesUnauthorized) WithPayload(payload *rest_model.APIErrorEnvelope) *ListServiceServicePoliciesUnauthorized {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the list service service policies unauthorized response
func (o *ListServiceServicePoliciesUnauthorized) SetPayload(payload *rest_model.APIErrorEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *ListServiceServicePoliciesUnauthorized) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(401)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

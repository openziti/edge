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

	"github.com/netfoundry/ziti-edge/models"
)

// ListServiceConfigOKCode is the HTTP code returned for type ListServiceConfigOK
const ListServiceConfigOKCode int = 200

/*ListServiceConfigOK A list of configs

swagger:response listServiceConfigOK
*/
type ListServiceConfigOK struct {

	/*
	  In: Body
	*/
	Payload *models.ListConfigsEnvelope `json:"body,omitempty"`
}

// NewListServiceConfigOK creates ListServiceConfigOK with default headers values
func NewListServiceConfigOK() *ListServiceConfigOK {

	return &ListServiceConfigOK{}
}

// WithPayload adds the payload to the list service config o k response
func (o *ListServiceConfigOK) WithPayload(payload *models.ListConfigsEnvelope) *ListServiceConfigOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the list service config o k response
func (o *ListServiceConfigOK) SetPayload(payload *models.ListConfigsEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *ListServiceConfigOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// ListServiceConfigUnauthorizedCode is the HTTP code returned for type ListServiceConfigUnauthorized
const ListServiceConfigUnauthorizedCode int = 401

/*ListServiceConfigUnauthorized The currently supplied session does not have the correct access rights to request this resource

swagger:response listServiceConfigUnauthorized
*/
type ListServiceConfigUnauthorized struct {

	/*
	  In: Body
	*/
	Payload *models.APIErrorEnvelope `json:"body,omitempty"`
}

// NewListServiceConfigUnauthorized creates ListServiceConfigUnauthorized with default headers values
func NewListServiceConfigUnauthorized() *ListServiceConfigUnauthorized {

	return &ListServiceConfigUnauthorized{}
}

// WithPayload adds the payload to the list service config unauthorized response
func (o *ListServiceConfigUnauthorized) WithPayload(payload *models.APIErrorEnvelope) *ListServiceConfigUnauthorized {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the list service config unauthorized response
func (o *ListServiceConfigUnauthorized) SetPayload(payload *models.APIErrorEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *ListServiceConfigUnauthorized) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(401)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

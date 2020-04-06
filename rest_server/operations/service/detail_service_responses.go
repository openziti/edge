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

// DetailServiceOKCode is the HTTP code returned for type DetailServiceOK
const DetailServiceOKCode int = 200

/*DetailServiceOK A single service

swagger:response detailServiceOK
*/
type DetailServiceOK struct {

	/*
	  In: Body
	*/
	Payload *rest_model.DetailServiceEnvelope `json:"body,omitempty"`
}

// NewDetailServiceOK creates DetailServiceOK with default headers values
func NewDetailServiceOK() *DetailServiceOK {

	return &DetailServiceOK{}
}

// WithPayload adds the payload to the detail service o k response
func (o *DetailServiceOK) WithPayload(payload *rest_model.DetailServiceEnvelope) *DetailServiceOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the detail service o k response
func (o *DetailServiceOK) SetPayload(payload *rest_model.DetailServiceEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *DetailServiceOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// DetailServiceUnauthorizedCode is the HTTP code returned for type DetailServiceUnauthorized
const DetailServiceUnauthorizedCode int = 401

/*DetailServiceUnauthorized The currently supplied session does not have the correct access rights to request this resource

swagger:response detailServiceUnauthorized
*/
type DetailServiceUnauthorized struct {

	/*
	  In: Body
	*/
	Payload *rest_model.APIErrorEnvelope `json:"body,omitempty"`
}

// NewDetailServiceUnauthorized creates DetailServiceUnauthorized with default headers values
func NewDetailServiceUnauthorized() *DetailServiceUnauthorized {

	return &DetailServiceUnauthorized{}
}

// WithPayload adds the payload to the detail service unauthorized response
func (o *DetailServiceUnauthorized) WithPayload(payload *rest_model.APIErrorEnvelope) *DetailServiceUnauthorized {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the detail service unauthorized response
func (o *DetailServiceUnauthorized) SetPayload(payload *rest_model.APIErrorEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *DetailServiceUnauthorized) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(401)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// DetailServiceNotFoundCode is the HTTP code returned for type DetailServiceNotFound
const DetailServiceNotFoundCode int = 404

/*DetailServiceNotFound The requested resource does not exist

swagger:response detailServiceNotFound
*/
type DetailServiceNotFound struct {

	/*
	  In: Body
	*/
	Payload *rest_model.APIErrorEnvelope `json:"body,omitempty"`
}

// NewDetailServiceNotFound creates DetailServiceNotFound with default headers values
func NewDetailServiceNotFound() *DetailServiceNotFound {

	return &DetailServiceNotFound{}
}

// WithPayload adds the payload to the detail service not found response
func (o *DetailServiceNotFound) WithPayload(payload *rest_model.APIErrorEnvelope) *DetailServiceNotFound {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the detail service not found response
func (o *DetailServiceNotFound) SetPayload(payload *rest_model.APIErrorEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *DetailServiceNotFound) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(404)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

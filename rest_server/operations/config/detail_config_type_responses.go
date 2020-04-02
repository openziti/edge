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

package config

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	"github.com/netfoundry/ziti-edge/models"
)

// DetailConfigTypeOKCode is the HTTP code returned for type DetailConfigTypeOK
const DetailConfigTypeOKCode int = 200

/*DetailConfigTypeOK A singular config-type resource

swagger:response detailConfigTypeOK
*/
type DetailConfigTypeOK struct {

	/*
	  In: Body
	*/
	Payload *models.DetailConfigTypeEnvelope `json:"body,omitempty"`
}

// NewDetailConfigTypeOK creates DetailConfigTypeOK with default headers values
func NewDetailConfigTypeOK() *DetailConfigTypeOK {

	return &DetailConfigTypeOK{}
}

// WithPayload adds the payload to the detail config type o k response
func (o *DetailConfigTypeOK) WithPayload(payload *models.DetailConfigTypeEnvelope) *DetailConfigTypeOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the detail config type o k response
func (o *DetailConfigTypeOK) SetPayload(payload *models.DetailConfigTypeEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *DetailConfigTypeOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// DetailConfigTypeUnauthorizedCode is the HTTP code returned for type DetailConfigTypeUnauthorized
const DetailConfigTypeUnauthorizedCode int = 401

/*DetailConfigTypeUnauthorized The currently supplied session does not have the correct access rights to request this resource

swagger:response detailConfigTypeUnauthorized
*/
type DetailConfigTypeUnauthorized struct {

	/*
	  In: Body
	*/
	Payload *models.APIErrorEnvelope `json:"body,omitempty"`
}

// NewDetailConfigTypeUnauthorized creates DetailConfigTypeUnauthorized with default headers values
func NewDetailConfigTypeUnauthorized() *DetailConfigTypeUnauthorized {

	return &DetailConfigTypeUnauthorized{}
}

// WithPayload adds the payload to the detail config type unauthorized response
func (o *DetailConfigTypeUnauthorized) WithPayload(payload *models.APIErrorEnvelope) *DetailConfigTypeUnauthorized {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the detail config type unauthorized response
func (o *DetailConfigTypeUnauthorized) SetPayload(payload *models.APIErrorEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *DetailConfigTypeUnauthorized) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(401)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// DetailConfigTypeNotFoundCode is the HTTP code returned for type DetailConfigTypeNotFound
const DetailConfigTypeNotFoundCode int = 404

/*DetailConfigTypeNotFound The requested resource does not exist

swagger:response detailConfigTypeNotFound
*/
type DetailConfigTypeNotFound struct {

	/*
	  In: Body
	*/
	Payload *models.APIErrorEnvelope `json:"body,omitempty"`
}

// NewDetailConfigTypeNotFound creates DetailConfigTypeNotFound with default headers values
func NewDetailConfigTypeNotFound() *DetailConfigTypeNotFound {

	return &DetailConfigTypeNotFound{}
}

// WithPayload adds the payload to the detail config type not found response
func (o *DetailConfigTypeNotFound) WithPayload(payload *models.APIErrorEnvelope) *DetailConfigTypeNotFound {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the detail config type not found response
func (o *DetailConfigTypeNotFound) SetPayload(payload *models.APIErrorEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *DetailConfigTypeNotFound) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(404)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

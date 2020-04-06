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

	"github.com/netfoundry/ziti-edge/rest_model"
)

// UpdateConfigOKCode is the HTTP code returned for type UpdateConfigOK
const UpdateConfigOKCode int = 200

/*UpdateConfigOK The update request was successful and the resource has been altered

swagger:response updateConfigOK
*/
type UpdateConfigOK struct {

	/*
	  In: Body
	*/
	Payload *rest_model.Empty `json:"body,omitempty"`
}

// NewUpdateConfigOK creates UpdateConfigOK with default headers values
func NewUpdateConfigOK() *UpdateConfigOK {

	return &UpdateConfigOK{}
}

// WithPayload adds the payload to the update config o k response
func (o *UpdateConfigOK) WithPayload(payload *rest_model.Empty) *UpdateConfigOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the update config o k response
func (o *UpdateConfigOK) SetPayload(payload *rest_model.Empty) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *UpdateConfigOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// UpdateConfigBadRequestCode is the HTTP code returned for type UpdateConfigBadRequest
const UpdateConfigBadRequestCode int = 400

/*UpdateConfigBadRequest The supplied request contains invalid fields or could not be parsed (json and non-json bodies). The error's code, message, and cause fields can be inspected for further information

swagger:response updateConfigBadRequest
*/
type UpdateConfigBadRequest struct {

	/*
	  In: Body
	*/
	Payload *rest_model.APIErrorEnvelope `json:"body,omitempty"`
}

// NewUpdateConfigBadRequest creates UpdateConfigBadRequest with default headers values
func NewUpdateConfigBadRequest() *UpdateConfigBadRequest {

	return &UpdateConfigBadRequest{}
}

// WithPayload adds the payload to the update config bad request response
func (o *UpdateConfigBadRequest) WithPayload(payload *rest_model.APIErrorEnvelope) *UpdateConfigBadRequest {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the update config bad request response
func (o *UpdateConfigBadRequest) SetPayload(payload *rest_model.APIErrorEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *UpdateConfigBadRequest) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(400)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// UpdateConfigUnauthorizedCode is the HTTP code returned for type UpdateConfigUnauthorized
const UpdateConfigUnauthorizedCode int = 401

/*UpdateConfigUnauthorized The currently supplied session does not have the correct access rights to request this resource

swagger:response updateConfigUnauthorized
*/
type UpdateConfigUnauthorized struct {

	/*
	  In: Body
	*/
	Payload *rest_model.APIErrorEnvelope `json:"body,omitempty"`
}

// NewUpdateConfigUnauthorized creates UpdateConfigUnauthorized with default headers values
func NewUpdateConfigUnauthorized() *UpdateConfigUnauthorized {

	return &UpdateConfigUnauthorized{}
}

// WithPayload adds the payload to the update config unauthorized response
func (o *UpdateConfigUnauthorized) WithPayload(payload *rest_model.APIErrorEnvelope) *UpdateConfigUnauthorized {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the update config unauthorized response
func (o *UpdateConfigUnauthorized) SetPayload(payload *rest_model.APIErrorEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *UpdateConfigUnauthorized) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(401)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// UpdateConfigNotFoundCode is the HTTP code returned for type UpdateConfigNotFound
const UpdateConfigNotFoundCode int = 404

/*UpdateConfigNotFound The requested resource does not exist

swagger:response updateConfigNotFound
*/
type UpdateConfigNotFound struct {

	/*
	  In: Body
	*/
	Payload *rest_model.APIErrorEnvelope `json:"body,omitempty"`
}

// NewUpdateConfigNotFound creates UpdateConfigNotFound with default headers values
func NewUpdateConfigNotFound() *UpdateConfigNotFound {

	return &UpdateConfigNotFound{}
}

// WithPayload adds the payload to the update config not found response
func (o *UpdateConfigNotFound) WithPayload(payload *rest_model.APIErrorEnvelope) *UpdateConfigNotFound {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the update config not found response
func (o *UpdateConfigNotFound) SetPayload(payload *rest_model.APIErrorEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *UpdateConfigNotFound) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(404)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

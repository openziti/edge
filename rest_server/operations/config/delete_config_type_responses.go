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

// DeleteConfigTypeOKCode is the HTTP code returned for type DeleteConfigTypeOK
const DeleteConfigTypeOKCode int = 200

/*DeleteConfigTypeOK The delete request was successful and the resource has been removed

swagger:response deleteConfigTypeOK
*/
type DeleteConfigTypeOK struct {

	/*
	  In: Body
	*/
	Payload *models.Empty `json:"body,omitempty"`
}

// NewDeleteConfigTypeOK creates DeleteConfigTypeOK with default headers values
func NewDeleteConfigTypeOK() *DeleteConfigTypeOK {

	return &DeleteConfigTypeOK{}
}

// WithPayload adds the payload to the delete config type o k response
func (o *DeleteConfigTypeOK) WithPayload(payload *models.Empty) *DeleteConfigTypeOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the delete config type o k response
func (o *DeleteConfigTypeOK) SetPayload(payload *models.Empty) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *DeleteConfigTypeOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// DeleteConfigTypeBadRequestCode is the HTTP code returned for type DeleteConfigTypeBadRequest
const DeleteConfigTypeBadRequestCode int = 400

/*DeleteConfigTypeBadRequest The supplied request contains invalid fields or could not be parsed (json and non-json bodies). The error's code, message, and cause fields can be inspected for further information

swagger:response deleteConfigTypeBadRequest
*/
type DeleteConfigTypeBadRequest struct {

	/*
	  In: Body
	*/
	Payload *models.APIErrorEnvelope `json:"body,omitempty"`
}

// NewDeleteConfigTypeBadRequest creates DeleteConfigTypeBadRequest with default headers values
func NewDeleteConfigTypeBadRequest() *DeleteConfigTypeBadRequest {

	return &DeleteConfigTypeBadRequest{}
}

// WithPayload adds the payload to the delete config type bad request response
func (o *DeleteConfigTypeBadRequest) WithPayload(payload *models.APIErrorEnvelope) *DeleteConfigTypeBadRequest {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the delete config type bad request response
func (o *DeleteConfigTypeBadRequest) SetPayload(payload *models.APIErrorEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *DeleteConfigTypeBadRequest) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(400)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// DeleteConfigTypeUnauthorizedCode is the HTTP code returned for type DeleteConfigTypeUnauthorized
const DeleteConfigTypeUnauthorizedCode int = 401

/*DeleteConfigTypeUnauthorized The currently supplied session does not have the correct access rights to request this resource

swagger:response deleteConfigTypeUnauthorized
*/
type DeleteConfigTypeUnauthorized struct {

	/*
	  In: Body
	*/
	Payload *models.APIErrorEnvelope `json:"body,omitempty"`
}

// NewDeleteConfigTypeUnauthorized creates DeleteConfigTypeUnauthorized with default headers values
func NewDeleteConfigTypeUnauthorized() *DeleteConfigTypeUnauthorized {

	return &DeleteConfigTypeUnauthorized{}
}

// WithPayload adds the payload to the delete config type unauthorized response
func (o *DeleteConfigTypeUnauthorized) WithPayload(payload *models.APIErrorEnvelope) *DeleteConfigTypeUnauthorized {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the delete config type unauthorized response
func (o *DeleteConfigTypeUnauthorized) SetPayload(payload *models.APIErrorEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *DeleteConfigTypeUnauthorized) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(401)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// DeleteConfigTypeConflictCode is the HTTP code returned for type DeleteConfigTypeConflict
const DeleteConfigTypeConflictCode int = 409

/*DeleteConfigTypeConflict The resource requested to be removed/altered cannot be as it is referenced by another object.

swagger:response deleteConfigTypeConflict
*/
type DeleteConfigTypeConflict struct {

	/*
	  In: Body
	*/
	Payload *models.APIErrorEnvelope `json:"body,omitempty"`
}

// NewDeleteConfigTypeConflict creates DeleteConfigTypeConflict with default headers values
func NewDeleteConfigTypeConflict() *DeleteConfigTypeConflict {

	return &DeleteConfigTypeConflict{}
}

// WithPayload adds the payload to the delete config type conflict response
func (o *DeleteConfigTypeConflict) WithPayload(payload *models.APIErrorEnvelope) *DeleteConfigTypeConflict {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the delete config type conflict response
func (o *DeleteConfigTypeConflict) SetPayload(payload *models.APIErrorEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *DeleteConfigTypeConflict) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(409)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

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

package auth_policy

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/openziti/edge/rest_model"
)

// UpdateAuthPolicyReader is a Reader for the UpdateAuthPolicy structure.
type UpdateAuthPolicyReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *UpdateAuthPolicyReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewUpdateAuthPolicyOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewUpdateAuthPolicyBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewUpdateAuthPolicyUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewUpdateAuthPolicyNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewUpdateAuthPolicyOK creates a UpdateAuthPolicyOK with default headers values
func NewUpdateAuthPolicyOK() *UpdateAuthPolicyOK {
	return &UpdateAuthPolicyOK{}
}

/* UpdateAuthPolicyOK describes a response with status code 200, with default header values.

The update request was successful and the resource has been altered
*/
type UpdateAuthPolicyOK struct {
	Payload *rest_model.Empty
}

func (o *UpdateAuthPolicyOK) Error() string {
	return fmt.Sprintf("[PUT /auth-policies/{id}][%d] updateAuthPolicyOK  %+v", 200, o.Payload)
}
func (o *UpdateAuthPolicyOK) GetPayload() *rest_model.Empty {
	return o.Payload
}

func (o *UpdateAuthPolicyOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.Empty)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateAuthPolicyBadRequest creates a UpdateAuthPolicyBadRequest with default headers values
func NewUpdateAuthPolicyBadRequest() *UpdateAuthPolicyBadRequest {
	return &UpdateAuthPolicyBadRequest{}
}

/* UpdateAuthPolicyBadRequest describes a response with status code 400, with default header values.

The supplied request contains invalid fields or could not be parsed (json and non-json bodies). The error's code, message, and cause fields can be inspected for further information
*/
type UpdateAuthPolicyBadRequest struct {
	Payload *rest_model.APIErrorEnvelope
}

func (o *UpdateAuthPolicyBadRequest) Error() string {
	return fmt.Sprintf("[PUT /auth-policies/{id}][%d] updateAuthPolicyBadRequest  %+v", 400, o.Payload)
}
func (o *UpdateAuthPolicyBadRequest) GetPayload() *rest_model.APIErrorEnvelope {
	return o.Payload
}

func (o *UpdateAuthPolicyBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.APIErrorEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateAuthPolicyUnauthorized creates a UpdateAuthPolicyUnauthorized with default headers values
func NewUpdateAuthPolicyUnauthorized() *UpdateAuthPolicyUnauthorized {
	return &UpdateAuthPolicyUnauthorized{}
}

/* UpdateAuthPolicyUnauthorized describes a response with status code 401, with default header values.

The currently supplied session does not have the correct access rights to request this resource
*/
type UpdateAuthPolicyUnauthorized struct {
	Payload *rest_model.APIErrorEnvelope
}

func (o *UpdateAuthPolicyUnauthorized) Error() string {
	return fmt.Sprintf("[PUT /auth-policies/{id}][%d] updateAuthPolicyUnauthorized  %+v", 401, o.Payload)
}
func (o *UpdateAuthPolicyUnauthorized) GetPayload() *rest_model.APIErrorEnvelope {
	return o.Payload
}

func (o *UpdateAuthPolicyUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.APIErrorEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateAuthPolicyNotFound creates a UpdateAuthPolicyNotFound with default headers values
func NewUpdateAuthPolicyNotFound() *UpdateAuthPolicyNotFound {
	return &UpdateAuthPolicyNotFound{}
}

/* UpdateAuthPolicyNotFound describes a response with status code 404, with default header values.

The requested resource does not exist
*/
type UpdateAuthPolicyNotFound struct {
	Payload *rest_model.APIErrorEnvelope
}

func (o *UpdateAuthPolicyNotFound) Error() string {
	return fmt.Sprintf("[PUT /auth-policies/{id}][%d] updateAuthPolicyNotFound  %+v", 404, o.Payload)
}
func (o *UpdateAuthPolicyNotFound) GetPayload() *rest_model.APIErrorEnvelope {
	return o.Payload
}

func (o *UpdateAuthPolicyNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.APIErrorEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

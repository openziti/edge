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

package service_policy

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/netfoundry/ziti-edge/rest_model"
)

// DeleteServicePolicyReader is a Reader for the DeleteServicePolicy structure.
type DeleteServicePolicyReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *DeleteServicePolicyReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewDeleteServicePolicyOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewDeleteServicePolicyBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewDeleteServicePolicyUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 409:
		result := NewDeleteServicePolicyConflict()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("unknown error", response, response.Code())
	}
}

// NewDeleteServicePolicyOK creates a DeleteServicePolicyOK with default headers values
func NewDeleteServicePolicyOK() *DeleteServicePolicyOK {
	return &DeleteServicePolicyOK{}
}

/*DeleteServicePolicyOK handles this case with default header values.

The delete request was successful and the resource has been removed
*/
type DeleteServicePolicyOK struct {
	Payload *rest_model.Empty
}

func (o *DeleteServicePolicyOK) Error() string {
	return fmt.Sprintf("[DELETE /service-policies/{id}][%d] deleteServicePolicyOK  %+v", 200, o.Payload)
}

func (o *DeleteServicePolicyOK) GetPayload() *rest_model.Empty {
	return o.Payload
}

func (o *DeleteServicePolicyOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.Empty)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteServicePolicyBadRequest creates a DeleteServicePolicyBadRequest with default headers values
func NewDeleteServicePolicyBadRequest() *DeleteServicePolicyBadRequest {
	return &DeleteServicePolicyBadRequest{}
}

/*DeleteServicePolicyBadRequest handles this case with default header values.

The supplied request contains invalid fields or could not be parsed (json and non-json bodies). The error's code, message, and cause fields can be inspected for further information
*/
type DeleteServicePolicyBadRequest struct {
	Payload *rest_model.APIErrorEnvelope
}

func (o *DeleteServicePolicyBadRequest) Error() string {
	return fmt.Sprintf("[DELETE /service-policies/{id}][%d] deleteServicePolicyBadRequest  %+v", 400, o.Payload)
}

func (o *DeleteServicePolicyBadRequest) GetPayload() *rest_model.APIErrorEnvelope {
	return o.Payload
}

func (o *DeleteServicePolicyBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.APIErrorEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteServicePolicyUnauthorized creates a DeleteServicePolicyUnauthorized with default headers values
func NewDeleteServicePolicyUnauthorized() *DeleteServicePolicyUnauthorized {
	return &DeleteServicePolicyUnauthorized{}
}

/*DeleteServicePolicyUnauthorized handles this case with default header values.

The currently supplied session does not have the correct access rights to request this resource
*/
type DeleteServicePolicyUnauthorized struct {
	Payload *rest_model.APIErrorEnvelope
}

func (o *DeleteServicePolicyUnauthorized) Error() string {
	return fmt.Sprintf("[DELETE /service-policies/{id}][%d] deleteServicePolicyUnauthorized  %+v", 401, o.Payload)
}

func (o *DeleteServicePolicyUnauthorized) GetPayload() *rest_model.APIErrorEnvelope {
	return o.Payload
}

func (o *DeleteServicePolicyUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.APIErrorEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteServicePolicyConflict creates a DeleteServicePolicyConflict with default headers values
func NewDeleteServicePolicyConflict() *DeleteServicePolicyConflict {
	return &DeleteServicePolicyConflict{}
}

/*DeleteServicePolicyConflict handles this case with default header values.

The resource requested to be removed/altered cannot be as it is referenced by another object.
*/
type DeleteServicePolicyConflict struct {
	Payload *rest_model.APIErrorEnvelope
}

func (o *DeleteServicePolicyConflict) Error() string {
	return fmt.Sprintf("[DELETE /service-policies/{id}][%d] deleteServicePolicyConflict  %+v", 409, o.Payload)
}

func (o *DeleteServicePolicyConflict) GetPayload() *rest_model.APIErrorEnvelope {
	return o.Payload
}

func (o *DeleteServicePolicyConflict) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.APIErrorEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

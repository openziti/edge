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
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/netfoundry/ziti-edge/models"
)

// DeleteServiceReader is a Reader for the DeleteService structure.
type DeleteServiceReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *DeleteServiceReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewDeleteServiceOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewDeleteServiceBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewDeleteServiceUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 409:
		result := NewDeleteServiceConflict()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("unknown error", response, response.Code())
	}
}

// NewDeleteServiceOK creates a DeleteServiceOK with default headers values
func NewDeleteServiceOK() *DeleteServiceOK {
	return &DeleteServiceOK{}
}

/*DeleteServiceOK handles this case with default header values.

The delete request was successful and the resource has been removed
*/
type DeleteServiceOK struct {
	Payload *models.Empty
}

func (o *DeleteServiceOK) Error() string {
	return fmt.Sprintf("[DELETE /services/{id}][%d] deleteServiceOK  %+v", 200, o.Payload)
}

func (o *DeleteServiceOK) GetPayload() *models.Empty {
	return o.Payload
}

func (o *DeleteServiceOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Empty)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteServiceBadRequest creates a DeleteServiceBadRequest with default headers values
func NewDeleteServiceBadRequest() *DeleteServiceBadRequest {
	return &DeleteServiceBadRequest{}
}

/*DeleteServiceBadRequest handles this case with default header values.

The supplied request contains invalid fields or could not be parsed (json and non-json bodies). The error's code, message, and cause fields can be inspected for further information
*/
type DeleteServiceBadRequest struct {
	Payload *models.APIErrorEnvelope
}

func (o *DeleteServiceBadRequest) Error() string {
	return fmt.Sprintf("[DELETE /services/{id}][%d] deleteServiceBadRequest  %+v", 400, o.Payload)
}

func (o *DeleteServiceBadRequest) GetPayload() *models.APIErrorEnvelope {
	return o.Payload
}

func (o *DeleteServiceBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.APIErrorEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteServiceUnauthorized creates a DeleteServiceUnauthorized with default headers values
func NewDeleteServiceUnauthorized() *DeleteServiceUnauthorized {
	return &DeleteServiceUnauthorized{}
}

/*DeleteServiceUnauthorized handles this case with default header values.

The currently supplied session does not have the correct access rights to request this resource
*/
type DeleteServiceUnauthorized struct {
	Payload *models.APIErrorEnvelope
}

func (o *DeleteServiceUnauthorized) Error() string {
	return fmt.Sprintf("[DELETE /services/{id}][%d] deleteServiceUnauthorized  %+v", 401, o.Payload)
}

func (o *DeleteServiceUnauthorized) GetPayload() *models.APIErrorEnvelope {
	return o.Payload
}

func (o *DeleteServiceUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.APIErrorEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteServiceConflict creates a DeleteServiceConflict with default headers values
func NewDeleteServiceConflict() *DeleteServiceConflict {
	return &DeleteServiceConflict{}
}

/*DeleteServiceConflict handles this case with default header values.

The resource requested to be removed/altered cannot be as it is referenced by another object.
*/
type DeleteServiceConflict struct {
	Payload *models.APIErrorEnvelope
}

func (o *DeleteServiceConflict) Error() string {
	return fmt.Sprintf("[DELETE /services/{id}][%d] deleteServiceConflict  %+v", 409, o.Payload)
}

func (o *DeleteServiceConflict) GetPayload() *models.APIErrorEnvelope {
	return o.Payload
}

func (o *DeleteServiceConflict) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.APIErrorEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

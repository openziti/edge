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
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/netfoundry/ziti-edge/rest_model"
)

// DeleteConfigTypeReader is a Reader for the DeleteConfigType structure.
type DeleteConfigTypeReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *DeleteConfigTypeReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewDeleteConfigTypeOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewDeleteConfigTypeBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewDeleteConfigTypeUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 409:
		result := NewDeleteConfigTypeConflict()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("unknown error", response, response.Code())
	}
}

// NewDeleteConfigTypeOK creates a DeleteConfigTypeOK with default headers values
func NewDeleteConfigTypeOK() *DeleteConfigTypeOK {
	return &DeleteConfigTypeOK{}
}

/*DeleteConfigTypeOK handles this case with default header values.

The delete request was successful and the resource has been removed
*/
type DeleteConfigTypeOK struct {
	Payload *rest_model.Empty
}

func (o *DeleteConfigTypeOK) Error() string {
	return fmt.Sprintf("[DELETE /config-types/{id}][%d] deleteConfigTypeOK  %+v", 200, o.Payload)
}

func (o *DeleteConfigTypeOK) GetPayload() *rest_model.Empty {
	return o.Payload
}

func (o *DeleteConfigTypeOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.Empty)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteConfigTypeBadRequest creates a DeleteConfigTypeBadRequest with default headers values
func NewDeleteConfigTypeBadRequest() *DeleteConfigTypeBadRequest {
	return &DeleteConfigTypeBadRequest{}
}

/*DeleteConfigTypeBadRequest handles this case with default header values.

The supplied request contains invalid fields or could not be parsed (json and non-json bodies). The error's code, message, and cause fields can be inspected for further information
*/
type DeleteConfigTypeBadRequest struct {
	Payload *rest_model.APIErrorEnvelope
}

func (o *DeleteConfigTypeBadRequest) Error() string {
	return fmt.Sprintf("[DELETE /config-types/{id}][%d] deleteConfigTypeBadRequest  %+v", 400, o.Payload)
}

func (o *DeleteConfigTypeBadRequest) GetPayload() *rest_model.APIErrorEnvelope {
	return o.Payload
}

func (o *DeleteConfigTypeBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.APIErrorEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteConfigTypeUnauthorized creates a DeleteConfigTypeUnauthorized with default headers values
func NewDeleteConfigTypeUnauthorized() *DeleteConfigTypeUnauthorized {
	return &DeleteConfigTypeUnauthorized{}
}

/*DeleteConfigTypeUnauthorized handles this case with default header values.

The currently supplied session does not have the correct access rights to request this resource
*/
type DeleteConfigTypeUnauthorized struct {
	Payload *rest_model.APIErrorEnvelope
}

func (o *DeleteConfigTypeUnauthorized) Error() string {
	return fmt.Sprintf("[DELETE /config-types/{id}][%d] deleteConfigTypeUnauthorized  %+v", 401, o.Payload)
}

func (o *DeleteConfigTypeUnauthorized) GetPayload() *rest_model.APIErrorEnvelope {
	return o.Payload
}

func (o *DeleteConfigTypeUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.APIErrorEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteConfigTypeConflict creates a DeleteConfigTypeConflict with default headers values
func NewDeleteConfigTypeConflict() *DeleteConfigTypeConflict {
	return &DeleteConfigTypeConflict{}
}

/*DeleteConfigTypeConflict handles this case with default header values.

The resource requested to be removed/altered cannot be as it is referenced by another object.
*/
type DeleteConfigTypeConflict struct {
	Payload *rest_model.APIErrorEnvelope
}

func (o *DeleteConfigTypeConflict) Error() string {
	return fmt.Sprintf("[DELETE /config-types/{id}][%d] deleteConfigTypeConflict  %+v", 409, o.Payload)
}

func (o *DeleteConfigTypeConflict) GetPayload() *rest_model.APIErrorEnvelope {
	return o.Payload
}

func (o *DeleteConfigTypeConflict) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.APIErrorEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

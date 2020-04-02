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

	"github.com/netfoundry/ziti-edge/models"
)

// PatchConfigTypeReader is a Reader for the PatchConfigType structure.
type PatchConfigTypeReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PatchConfigTypeReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPatchConfigTypeOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewPatchConfigTypeBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewPatchConfigTypeUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewPatchConfigTypeNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("unknown error", response, response.Code())
	}
}

// NewPatchConfigTypeOK creates a PatchConfigTypeOK with default headers values
func NewPatchConfigTypeOK() *PatchConfigTypeOK {
	return &PatchConfigTypeOK{}
}

/*PatchConfigTypeOK handles this case with default header values.

The patch request was successful and the resource has been altered
*/
type PatchConfigTypeOK struct {
	Payload *models.Empty
}

func (o *PatchConfigTypeOK) Error() string {
	return fmt.Sprintf("[PATCH /config-types/{id}][%d] patchConfigTypeOK  %+v", 200, o.Payload)
}

func (o *PatchConfigTypeOK) GetPayload() *models.Empty {
	return o.Payload
}

func (o *PatchConfigTypeOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Empty)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPatchConfigTypeBadRequest creates a PatchConfigTypeBadRequest with default headers values
func NewPatchConfigTypeBadRequest() *PatchConfigTypeBadRequest {
	return &PatchConfigTypeBadRequest{}
}

/*PatchConfigTypeBadRequest handles this case with default header values.

The supplied request contains invalid fields or could not be parsed (json and non-json bodies). The error's code, message, and cause fields can be inspected for further information
*/
type PatchConfigTypeBadRequest struct {
	Payload *models.APIErrorEnvelope
}

func (o *PatchConfigTypeBadRequest) Error() string {
	return fmt.Sprintf("[PATCH /config-types/{id}][%d] patchConfigTypeBadRequest  %+v", 400, o.Payload)
}

func (o *PatchConfigTypeBadRequest) GetPayload() *models.APIErrorEnvelope {
	return o.Payload
}

func (o *PatchConfigTypeBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.APIErrorEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPatchConfigTypeUnauthorized creates a PatchConfigTypeUnauthorized with default headers values
func NewPatchConfigTypeUnauthorized() *PatchConfigTypeUnauthorized {
	return &PatchConfigTypeUnauthorized{}
}

/*PatchConfigTypeUnauthorized handles this case with default header values.

The currently supplied session does not have the correct access rights to request this resource
*/
type PatchConfigTypeUnauthorized struct {
	Payload *models.APIErrorEnvelope
}

func (o *PatchConfigTypeUnauthorized) Error() string {
	return fmt.Sprintf("[PATCH /config-types/{id}][%d] patchConfigTypeUnauthorized  %+v", 401, o.Payload)
}

func (o *PatchConfigTypeUnauthorized) GetPayload() *models.APIErrorEnvelope {
	return o.Payload
}

func (o *PatchConfigTypeUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.APIErrorEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPatchConfigTypeNotFound creates a PatchConfigTypeNotFound with default headers values
func NewPatchConfigTypeNotFound() *PatchConfigTypeNotFound {
	return &PatchConfigTypeNotFound{}
}

/*PatchConfigTypeNotFound handles this case with default header values.

The requested resource does not exist
*/
type PatchConfigTypeNotFound struct {
	Payload *models.APIErrorEnvelope
}

func (o *PatchConfigTypeNotFound) Error() string {
	return fmt.Sprintf("[PATCH /config-types/{id}][%d] patchConfigTypeNotFound  %+v", 404, o.Payload)
}

func (o *PatchConfigTypeNotFound) GetPayload() *models.APIErrorEnvelope {
	return o.Payload
}

func (o *PatchConfigTypeNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.APIErrorEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

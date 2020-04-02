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

package ca

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/netfoundry/ziti-edge/models"
)

// CreateCAReader is a Reader for the CreateCA structure.
type CreateCAReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CreateCAReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewCreateCAOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewCreateCABadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewCreateCAUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("unknown error", response, response.Code())
	}
}

// NewCreateCAOK creates a CreateCAOK with default headers values
func NewCreateCAOK() *CreateCAOK {
	return &CreateCAOK{}
}

/*CreateCAOK handles this case with default header values.

The create request was successful and the resource has been added at the following location
*/
type CreateCAOK struct {
	Payload *models.Create
}

func (o *CreateCAOK) Error() string {
	return fmt.Sprintf("[POST /cas][%d] createCaOK  %+v", 200, o.Payload)
}

func (o *CreateCAOK) GetPayload() *models.Create {
	return o.Payload
}

func (o *CreateCAOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Create)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateCABadRequest creates a CreateCABadRequest with default headers values
func NewCreateCABadRequest() *CreateCABadRequest {
	return &CreateCABadRequest{}
}

/*CreateCABadRequest handles this case with default header values.

The supplied request contains invalid fields or could not be parsed (json and non-json bodies). The error's code, message, and cause fields can be inspected for further information
*/
type CreateCABadRequest struct {
	Payload *models.APIErrorEnvelope
}

func (o *CreateCABadRequest) Error() string {
	return fmt.Sprintf("[POST /cas][%d] createCaBadRequest  %+v", 400, o.Payload)
}

func (o *CreateCABadRequest) GetPayload() *models.APIErrorEnvelope {
	return o.Payload
}

func (o *CreateCABadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.APIErrorEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateCAUnauthorized creates a CreateCAUnauthorized with default headers values
func NewCreateCAUnauthorized() *CreateCAUnauthorized {
	return &CreateCAUnauthorized{}
}

/*CreateCAUnauthorized handles this case with default header values.

The currently supplied session does not have the correct access rights to request this resource
*/
type CreateCAUnauthorized struct {
	Payload *models.APIErrorEnvelope
}

func (o *CreateCAUnauthorized) Error() string {
	return fmt.Sprintf("[POST /cas][%d] createCaUnauthorized  %+v", 401, o.Payload)
}

func (o *CreateCAUnauthorized) GetPayload() *models.APIErrorEnvelope {
	return o.Payload
}

func (o *CreateCAUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.APIErrorEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

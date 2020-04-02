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

package current_api_session

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/netfoundry/ziti-edge/models"
)

// GetCurrentIdentityReader is a Reader for the GetCurrentIdentity structure.
type GetCurrentIdentityReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetCurrentIdentityReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetCurrentIdentityOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewGetCurrentIdentityUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("unknown error", response, response.Code())
	}
}

// NewGetCurrentIdentityOK creates a GetCurrentIdentityOK with default headers values
func NewGetCurrentIdentityOK() *GetCurrentIdentityOK {
	return &GetCurrentIdentityOK{}
}

/*GetCurrentIdentityOK handles this case with default header values.

The identity associated with the API Session used to issue the request
*/
type GetCurrentIdentityOK struct {
	Payload *models.CurrentIdentityDetailEnvelope
}

func (o *GetCurrentIdentityOK) Error() string {
	return fmt.Sprintf("[GET /current-identity][%d] getCurrentIdentityOK  %+v", 200, o.Payload)
}

func (o *GetCurrentIdentityOK) GetPayload() *models.CurrentIdentityDetailEnvelope {
	return o.Payload
}

func (o *GetCurrentIdentityOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.CurrentIdentityDetailEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetCurrentIdentityUnauthorized creates a GetCurrentIdentityUnauthorized with default headers values
func NewGetCurrentIdentityUnauthorized() *GetCurrentIdentityUnauthorized {
	return &GetCurrentIdentityUnauthorized{}
}

/*GetCurrentIdentityUnauthorized handles this case with default header values.

The currently supplied session does not have the correct access rights to request this resource
*/
type GetCurrentIdentityUnauthorized struct {
	Payload *models.APIErrorEnvelope
}

func (o *GetCurrentIdentityUnauthorized) Error() string {
	return fmt.Sprintf("[GET /current-identity][%d] getCurrentIdentityUnauthorized  %+v", 401, o.Payload)
}

func (o *GetCurrentIdentityUnauthorized) GetPayload() *models.APIErrorEnvelope {
	return o.Payload
}

func (o *GetCurrentIdentityUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.APIErrorEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

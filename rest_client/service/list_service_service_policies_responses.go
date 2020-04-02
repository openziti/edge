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

// ListServiceServicePoliciesReader is a Reader for the ListServiceServicePolicies structure.
type ListServiceServicePoliciesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ListServiceServicePoliciesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewListServiceServicePoliciesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewListServiceServicePoliciesUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("unknown error", response, response.Code())
	}
}

// NewListServiceServicePoliciesOK creates a ListServiceServicePoliciesOK with default headers values
func NewListServiceServicePoliciesOK() *ListServiceServicePoliciesOK {
	return &ListServiceServicePoliciesOK{}
}

/*ListServiceServicePoliciesOK handles this case with default header values.

A list of service policies
*/
type ListServiceServicePoliciesOK struct {
	Payload *models.ListServicePoliciesEnvelope
}

func (o *ListServiceServicePoliciesOK) Error() string {
	return fmt.Sprintf("[GET /services/{id}/service-policies][%d] listServiceServicePoliciesOK  %+v", 200, o.Payload)
}

func (o *ListServiceServicePoliciesOK) GetPayload() *models.ListServicePoliciesEnvelope {
	return o.Payload
}

func (o *ListServiceServicePoliciesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ListServicePoliciesEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListServiceServicePoliciesUnauthorized creates a ListServiceServicePoliciesUnauthorized with default headers values
func NewListServiceServicePoliciesUnauthorized() *ListServiceServicePoliciesUnauthorized {
	return &ListServiceServicePoliciesUnauthorized{}
}

/*ListServiceServicePoliciesUnauthorized handles this case with default header values.

The currently supplied session does not have the correct access rights to request this resource
*/
type ListServiceServicePoliciesUnauthorized struct {
	Payload *models.APIErrorEnvelope
}

func (o *ListServiceServicePoliciesUnauthorized) Error() string {
	return fmt.Sprintf("[GET /services/{id}/service-policies][%d] listServiceServicePoliciesUnauthorized  %+v", 401, o.Payload)
}

func (o *ListServiceServicePoliciesUnauthorized) GetPayload() *models.APIErrorEnvelope {
	return o.Payload
}

func (o *ListServiceServicePoliciesUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.APIErrorEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

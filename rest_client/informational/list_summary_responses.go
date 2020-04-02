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

package informational

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/netfoundry/ziti-edge/models"
)

// ListSummaryReader is a Reader for the ListSummary structure.
type ListSummaryReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ListSummaryReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewListSummaryOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewListSummaryUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("unknown error", response, response.Code())
	}
}

// NewListSummaryOK creates a ListSummaryOK with default headers values
func NewListSummaryOK() *ListSummaryOK {
	return &ListSummaryOK{}
}

/*ListSummaryOK handles this case with default header values.

Entity counts scopped to the current identitie's access
*/
type ListSummaryOK struct {
	Payload *models.ListSummaryCountsEnvelope
}

func (o *ListSummaryOK) Error() string {
	return fmt.Sprintf("[GET /summary][%d] listSummaryOK  %+v", 200, o.Payload)
}

func (o *ListSummaryOK) GetPayload() *models.ListSummaryCountsEnvelope {
	return o.Payload
}

func (o *ListSummaryOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ListSummaryCountsEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListSummaryUnauthorized creates a ListSummaryUnauthorized with default headers values
func NewListSummaryUnauthorized() *ListSummaryUnauthorized {
	return &ListSummaryUnauthorized{}
}

/*ListSummaryUnauthorized handles this case with default header values.

The currently supplied session does not have the correct access rights to request this resource
*/
type ListSummaryUnauthorized struct {
	Payload *models.APIErrorEnvelope
}

func (o *ListSummaryUnauthorized) Error() string {
	return fmt.Sprintf("[GET /summary][%d] listSummaryUnauthorized  %+v", 401, o.Payload)
}

func (o *ListSummaryUnauthorized) GetPayload() *models.APIErrorEnvelope {
	return o.Payload
}

func (o *ListSummaryUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.APIErrorEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

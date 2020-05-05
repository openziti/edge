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

package identity

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"net/http"
	"time"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	cr "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
)

// NewListIdentityServicesParams creates a new ListIdentityServicesParams object
// with the default values initialized.
func NewListIdentityServicesParams() *ListIdentityServicesParams {
	var ()
	return &ListIdentityServicesParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewListIdentityServicesParamsWithTimeout creates a new ListIdentityServicesParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewListIdentityServicesParamsWithTimeout(timeout time.Duration) *ListIdentityServicesParams {
	var ()
	return &ListIdentityServicesParams{

		timeout: timeout,
	}
}

// NewListIdentityServicesParamsWithContext creates a new ListIdentityServicesParams object
// with the default values initialized, and the ability to set a context for a request
func NewListIdentityServicesParamsWithContext(ctx context.Context) *ListIdentityServicesParams {
	var ()
	return &ListIdentityServicesParams{

		Context: ctx,
	}
}

// NewListIdentityServicesParamsWithHTTPClient creates a new ListIdentityServicesParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewListIdentityServicesParamsWithHTTPClient(client *http.Client) *ListIdentityServicesParams {
	var ()
	return &ListIdentityServicesParams{
		HTTPClient: client,
	}
}

/*ListIdentityServicesParams contains all the parameters to send to the API endpoint
for the list identity services operation typically these are written to a http.Request
*/
type ListIdentityServicesParams struct {

	/*ID
	  The id of the requested resource

	*/
	ID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the list identity services params
func (o *ListIdentityServicesParams) WithTimeout(timeout time.Duration) *ListIdentityServicesParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the list identity services params
func (o *ListIdentityServicesParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the list identity services params
func (o *ListIdentityServicesParams) WithContext(ctx context.Context) *ListIdentityServicesParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the list identity services params
func (o *ListIdentityServicesParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the list identity services params
func (o *ListIdentityServicesParams) WithHTTPClient(client *http.Client) *ListIdentityServicesParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the list identity services params
func (o *ListIdentityServicesParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithID adds the id to the list identity services params
func (o *ListIdentityServicesParams) WithID(id string) *ListIdentityServicesParams {
	o.SetID(id)
	return o
}

// SetID adds the id to the list identity services params
func (o *ListIdentityServicesParams) SetID(id string) {
	o.ID = id
}

// WriteToRequest writes these params to a swagger request
func (o *ListIdentityServicesParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param id
	if err := r.SetPathParam("id", o.ID); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

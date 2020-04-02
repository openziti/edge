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

package session

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

// NewDeleteSessionParams creates a new DeleteSessionParams object
// with the default values initialized.
func NewDeleteSessionParams() *DeleteSessionParams {
	var ()
	return &DeleteSessionParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewDeleteSessionParamsWithTimeout creates a new DeleteSessionParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewDeleteSessionParamsWithTimeout(timeout time.Duration) *DeleteSessionParams {
	var ()
	return &DeleteSessionParams{

		timeout: timeout,
	}
}

// NewDeleteSessionParamsWithContext creates a new DeleteSessionParams object
// with the default values initialized, and the ability to set a context for a request
func NewDeleteSessionParamsWithContext(ctx context.Context) *DeleteSessionParams {
	var ()
	return &DeleteSessionParams{

		Context: ctx,
	}
}

// NewDeleteSessionParamsWithHTTPClient creates a new DeleteSessionParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewDeleteSessionParamsWithHTTPClient(client *http.Client) *DeleteSessionParams {
	var ()
	return &DeleteSessionParams{
		HTTPClient: client,
	}
}

/*DeleteSessionParams contains all the parameters to send to the API endpoint
for the delete session operation typically these are written to a http.Request
*/
type DeleteSessionParams struct {

	/*ID
	  The id of the requested resource

	*/
	ID strfmt.UUID

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the delete session params
func (o *DeleteSessionParams) WithTimeout(timeout time.Duration) *DeleteSessionParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the delete session params
func (o *DeleteSessionParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the delete session params
func (o *DeleteSessionParams) WithContext(ctx context.Context) *DeleteSessionParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the delete session params
func (o *DeleteSessionParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the delete session params
func (o *DeleteSessionParams) WithHTTPClient(client *http.Client) *DeleteSessionParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the delete session params
func (o *DeleteSessionParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithID adds the id to the delete session params
func (o *DeleteSessionParams) WithID(id strfmt.UUID) *DeleteSessionParams {
	o.SetID(id)
	return o
}

// SetID adds the id to the delete session params
func (o *DeleteSessionParams) SetID(id strfmt.UUID) {
	o.ID = id
}

// WriteToRequest writes these params to a swagger request
func (o *DeleteSessionParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param id
	if err := r.SetPathParam("id", o.ID.String()); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

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

package enroll

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

// NewPostEnrollOttcaParams creates a new PostEnrollOttcaParams object
// with the default values initialized.
func NewPostEnrollOttcaParams() *PostEnrollOttcaParams {
	var ()
	return &PostEnrollOttcaParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewPostEnrollOttcaParamsWithTimeout creates a new PostEnrollOttcaParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewPostEnrollOttcaParamsWithTimeout(timeout time.Duration) *PostEnrollOttcaParams {
	var ()
	return &PostEnrollOttcaParams{

		timeout: timeout,
	}
}

// NewPostEnrollOttcaParamsWithContext creates a new PostEnrollOttcaParams object
// with the default values initialized, and the ability to set a context for a request
func NewPostEnrollOttcaParamsWithContext(ctx context.Context) *PostEnrollOttcaParams {
	var ()
	return &PostEnrollOttcaParams{

		Context: ctx,
	}
}

// NewPostEnrollOttcaParamsWithHTTPClient creates a new PostEnrollOttcaParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewPostEnrollOttcaParamsWithHTTPClient(client *http.Client) *PostEnrollOttcaParams {
	var ()
	return &PostEnrollOttcaParams{
		HTTPClient: client,
	}
}

/*PostEnrollOttcaParams contains all the parameters to send to the API endpoint
for the post enroll ottca operation typically these are written to a http.Request
*/
type PostEnrollOttcaParams struct {

	/*Token*/
	Token strfmt.UUID

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the post enroll ottca params
func (o *PostEnrollOttcaParams) WithTimeout(timeout time.Duration) *PostEnrollOttcaParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the post enroll ottca params
func (o *PostEnrollOttcaParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the post enroll ottca params
func (o *PostEnrollOttcaParams) WithContext(ctx context.Context) *PostEnrollOttcaParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the post enroll ottca params
func (o *PostEnrollOttcaParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the post enroll ottca params
func (o *PostEnrollOttcaParams) WithHTTPClient(client *http.Client) *PostEnrollOttcaParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the post enroll ottca params
func (o *PostEnrollOttcaParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithToken adds the token to the post enroll ottca params
func (o *PostEnrollOttcaParams) WithToken(token strfmt.UUID) *PostEnrollOttcaParams {
	o.SetToken(token)
	return o
}

// SetToken adds the token to the post enroll ottca params
func (o *PostEnrollOttcaParams) SetToken(token strfmt.UUID) {
	o.Token = token
}

// WriteToRequest writes these params to a swagger request
func (o *PostEnrollOttcaParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// query param token
	qrToken := o.Token
	qToken := qrToken.String()
	if qToken != "" {
		if err := r.SetQueryParam("token", qToken); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

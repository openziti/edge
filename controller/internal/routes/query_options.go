/*
	Copyright 2019 NetFoundry, Inc.

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

	https://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
*/

package routes

import (
	"fmt"
	"github.com/michaelquigley/pfxlog"
	"github.com/netfoundry/ziti-edge/controller/predicate"
	"github.com/netfoundry/ziti-foundation/storage/ast"
	"github.com/netfoundry/ziti-foundation/storage/boltz"
	"strconv"
	"strings"
)

const (
	LimitMax      = 500
	OffsetMax     = 100000
	LimitDefault  = 10
	OffsetDefault = 0
)

type QueryOptions struct {
	Predicate string
	Sort      string
	Paging    *predicate.Paging
}

func (qo *QueryOptions) String() string {
	if qo == nil {
		return "nil"
	}
	return fmt.Sprintf("[QueryOption Predicate: '%v', Sort: '%v', Paging: '%v']", qo.Predicate, qo.Sort, qo.Paging)
}

func (qo *QueryOptions) ValidateAndCorrect() {
	// Sort limit is handled in ScanEntityImpl.NewScanner
	if qo.Paging == nil {
		qo.Paging = &predicate.Paging{
			Limit:  LimitDefault,
			Offset: OffsetDefault,
		}
	} else {
		if qo.Paging.Limit > LimitMax {
			qo.Paging.Limit = LimitMax
		}

		if qo.Paging.Limit <= 0 {
			qo.Paging.Limit = LimitDefault
		}

		if qo.Paging.Offset > OffsetMax {
			qo.Paging.Offset = OffsetMax
		}

		if qo.Paging.Offset <= 0 {
			qo.Paging.Offset = OffsetDefault
		}
	}
}

func (qo *QueryOptions) getFullQuery(store boltz.CrudStore) (string, error) {
	if qo.Predicate == "" {
		qo.Predicate = "true"
	}

	query, err := ast.Parse(store, qo.Predicate)
	if err != nil {
		return "", err
	}

	if err = boltz.ValidateSymbolsArePublic(query, store); err != nil {
		return "", err
	}

	pfxlog.Logger().Debugf("query: %v", qo)

	if qo.Paging != nil {
		if query.GetLimit() == nil {
			if qo.Paging.ReturnAll {
				query.SetLimit(-1)
			} else {
				query.SetLimit(qo.Paging.Limit)
			}
		}
		if query.GetSkip() == nil {
			query.SetSkip(qo.Paging.Offset)
		}
	}
	builder := &strings.Builder{}
	builder.WriteString(query.GetPredicate().String())

	// sort out sorts
	sortFields := query.GetSortFields()
	if len(sortFields) > 0 {
		builder.WriteString(" sort by ")
		builder.WriteString(sortFields[0].String())
		for _, sortField := range sortFields[1:] {
			builder.WriteString(", ")
			builder.WriteString(sortField.String())
		}
	} else if qo.Sort != "" {
		builder.WriteString(" sort by ")
		builder.WriteString(qo.Sort)
	}

	if query.GetSkip() != nil {
		builder.WriteString(" skip ")
		builder.WriteString(strconv.FormatInt(*query.GetSkip(), 10))
	}

	if query.GetLimit() != nil {
		builder.WriteString(" limit ")
		if *query.GetLimit() == -1 {
			builder.WriteString("none")
		} else {
			builder.WriteString(strconv.FormatInt(*query.GetLimit(), 10))
		}
	}

	return builder.String(), nil
}

// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"github.com/theseion/crs-toolchain/v2/processors"
)

type Indent int

type Assembler Operator

// TODO: Peekerator just has a compatible type, needs to be implemented.
func Peekerator(s []string) string {
	//p := strings.NewReader(s)
	return s[0]
}

func NewAssembler(ctx *processors.Context) *Assembler {
	a := &Assembler{
		ctx: ctx,
	}
	return a
}

func (a *Assembler) Preprocess(s string) (string, error) {
	//TODO: Implement
	return "TODO", nil
}

func (a *Assembler) Run(s string) (string, error) {
	//TODO: Implement
	return "TODO", nil
}

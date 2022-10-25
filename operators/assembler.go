// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package operators

import "github.com/theseion/crs-toolchain/v2/processors"

type Assembler struct {
	ctx *processors.Context
}

func Peekerator(s []string) {
	//TODO: is this a type?
}

func NewAssembler(ctx *processors.Context) *Assembler {
	a := &Assembler{
		ctx: ctx,
	}
	return a
}

func (a *Assembler) Preprocess() (string, error) {
	//TODO: Implement
	return "TODO", nil
}

func (a *Assembler) Run() (string, error) {
	//TODO: Implement
	return "TODO", nil
}

// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package processors

import (
	"github.com/rs/zerolog/log"
)

var logger = log.With().Str("component", "processors").Logger()

type Processor struct {
	ctx   *Context
	lines []string
}

type IProcessor interface {
	HasBody() bool
	ProcessLine(line string)
	Complete() []string
}

// NewProcessor creates a new processor with defaults.
func NewProcessor() *Processor {
	return NewProcessorWithContext(NewContext())
}

// NewProcessorWithContext creates a new processor with passed context.
func NewProcessorWithContext(ctx *Context) *Processor {
	p := &Processor{
		ctx:   ctx,
		lines: []string{},
	}
	return p
}

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
	// ProcessLine applies the processors logic to a single line
	ProcessLine(line string) error
	// Complete finalizes the processor, producing its output
	Complete() ([]string, error)
	// Consume applies the state of a nested processor
	Consume([]string) error
}

// NewProcessor creates a new processor with passed context.
func NewProcessor(ctx *Context) *Processor {
	return &Processor{
		ctx:   ctx,
		lines: []string{},
	}
}

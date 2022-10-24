// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package processors

import (
	"regexp"
)

const (
	AssembleInput  string = `^\s*##!=<\s*(.*)$`
	AssembleOutput string = `^\s*##!=>\s*(.*)$`
)

type Assemble struct {
	proc   *Processor
	input  *regexp.Regexp
	output *regexp.Regexp
	stash  map[string]string
}

// NewAssemble creates a new assemble processor
func NewAssemble(ctx *Context) Assemble {
	a := Assemble{
		proc: &Processor{
			ctx:          ctx,
			lines:        []string{},
			commentRegex: regexp.MustCompile(`^##!`),
		},
		input:  regexp.MustCompile(AssembleInput),
		output: regexp.MustCompile(AssembleOutput),
		stash:  make(map[string]string),
	}

	return a
}

// ProcessLine implements the line processor
func (a *Assemble) ProcessLine(line string) {
	//TODO: add real implementation
	a.proc.lines = append(a.proc.lines, line)
}

func (a *Assemble) HasBody() bool {
	//TODO: add real implementation
	return true
}

func (a *Assemble) Complete() []string {
	//TODO: add real implementation
	return a.proc.lines
}

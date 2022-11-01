// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package processors

import (
	"regexp"

	"github.com/itchyny/rassemble-go"
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
func NewAssemble(ctx *Context) *Assemble {
	a := &Assemble{
		proc:   NewProcessor(ctx),
		input:  regexp.MustCompile(AssembleInput),
		output: regexp.MustCompile(AssembleOutput),
		stash:  make(map[string]string),
	}

	return a
}

// ProcessLine implements the line processor
func (a *Assemble) ProcessLine(line string) {
	a.proc.lines = append(a.proc.lines, line)
}

func (a *Assemble) HasBody() bool {
	return true
}

func (a *Assemble) Complete() ([]string, error) {
	if len(a.proc.lines) == 0 {
		return []string{}, nil
	}
	assembly, err := rassemble.Join(a.proc.lines)
	if err != nil {
		return nil, err
	}
	return []string{assembly}, nil
}

func (a *Assemble) Consume(lines []string) {
	for _, line := range lines {
		a.ProcessLine(line)
	}
}

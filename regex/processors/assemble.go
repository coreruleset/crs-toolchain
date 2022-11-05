// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package processors

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/itchyny/rassemble-go"
)

const (
	AssembleInput  string = `^\s*##!=<\s*(.*)$`
	AssembleOutput string = `^\s*##!=>\s*(.*)$`
)

type Assemble struct {
	proc        *Processor
	inputRegex  *regexp.Regexp
	outputRegex *regexp.Regexp
	output      strings.Builder
}

// NewAssemble creates a new assemble processor
func NewAssemble(ctx *Context) *Assemble {
	return &Assemble{
		proc:        NewProcessor(ctx),
		inputRegex:  regexp.MustCompile(AssembleInput),
		outputRegex: regexp.MustCompile(AssembleOutput),
	}
}

// ProcessLine applies the processors logic to a single line
func (a *Assemble) ProcessLine(line string) {
	match := a.inputRegex.FindStringSubmatch(line)
	if len(match) > 0 {
		if err := a.store(match[1]); err != nil {
			logger.Fatal().Err(err).Msgf("Failed to store input: %s", line)
		}
		return
	}

	match = a.outputRegex.FindStringSubmatch(line)
	if len(match) > 0 {
		if err := a.append(match[1]); err != nil {
			logger.Fatal().Err(err).Msgf("Failed to append input: %s", line)
		}
	} else {
		a.proc.lines = append(a.proc.lines, line)
	}
}

// Complete finalizes the processor, producing its output
func (a *Assemble) Complete() ([]string, error) {
	logger.Trace().Msg("Completing assembly")
	regex, err := a.runAssemble()
	if err != nil {
		return nil, err
	}

	result := a.wrapCompletedAssembly(regex)
	logger.Debug().Msgf("Completed assembly: %s", result)

	if result == "" {
		return []string{}, nil
	}

	return []string{result}, nil
}

// Consume applies the state of a nested processor
func (a *Assemble) Consume(lines []string) {
	for _, line := range lines {
		a.ProcessLine(line)
	}
}

func (a *Assemble) store(identifier string) error {
	if len(identifier) == 0 {
		return errors.New("missing identifier for input marker")
	}

	if err := a.append(""); err != nil {
		return err
	}

	outputString := a.output.String()
	// reset output, the next call to `Complete` should not print
	// the value we just stored
	a.output.Reset()

	logger.Debug().Msgf("Storing expression at %s: %s", identifier, outputString)
	a.proc.ctx.stash[identifier] = outputString
	return nil
}

func (a *Assemble) append(identifier string) error {
	if len(identifier) == 0 {
		if len(identifier) == 1 {
			// Treat as literal, could be start of a group or a range expresssion.
			// Those can not be parsed by rassemble-go, since they are not valid
			// expressions.
			a.output.WriteString(a.proc.lines[0])
			a.proc.lines = []string{}
		}
		regex, err := a.runAssemble()
		if err != nil {
			return err
		}
		_, err = a.output.WriteString(regex)
		if err != nil {
			return err
		}
	} else {
		logger.Debug().Msgf("Appending stored expression at %s", identifier)
		fmt.Print(a.proc.ctx.stash[identifier])
		_, err := a.output.WriteString(a.proc.ctx.stash[identifier])
		if err != nil {
			return err
		}
	}
	return nil
}

func (a *Assemble) runAssemble() (regex string, err error) {
	if len(a.proc.lines) == 0 {
		return "", nil
	}

	regex, err = rassemble.Join(a.proc.lines)
	if err != nil {
		return "", err
	}

	a.proc.lines = []string{}
	return regex, nil
}
func (a *Assemble) wrapCompletedAssembly(regex string) (result string) {
	if len(regex) == 0 && a.output.Len() == 0 {
		return ""
	} else if a.output.Len() > 0 && len(regex) > 0 {
		result = fmt.Sprint("(?:", a.output.String(), ")(?:", regex, ")")
	} else if a.output.Len() > 0 {
		result = fmt.Sprint("(?:", a.output.String(), ")")
	} else if len(regex) == 0 {
		result = ""
	} else {
		result = fmt.Sprint("(?:", regex, ")")
	}

	return result
}

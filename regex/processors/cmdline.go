// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package processors

import (
	"bytes"
	"errors"
	"strings"

	"github.com/itchyny/rassemble-go"
)

const (
	CmdLineUndefined CmdLineType = iota
	CmdLineUnix
	CmdLineWindows
)
const (
	evasionPattern EvasionPatterns = iota
	suffixPattern
	suffixExpandedCommand
)

type CmdLineType int
type EvasionPatterns int

type CmdLine struct {
	proc            *Processor
	cmdType         CmdLineType
	evasionPatterns map[EvasionPatterns]string
}

// CmdLineTypeFromString will return a CmdLineType based on the string you enter, or an CmdLineUndefined and a new error.
func CmdLineTypeFromString(t string) (CmdLineType, error) {
	switch t {
	case "unix":
		return CmdLineUnix, nil
	case "windows":
		return CmdLineWindows, nil
	default:
		return CmdLineUndefined, errors.New("bad cmdline option")
	}

}

// NewCmdLine creates a new cmdline processor
func NewCmdLine(ctx *Context, cmdType CmdLineType) *CmdLine {
	a := &CmdLine{
		proc:            NewProcessor(ctx),
		cmdType:         cmdType,
		evasionPatterns: make(map[EvasionPatterns]string),
	}

	// Now add evasion patterns
	// We will insert these sequences between characters to prevent evasion.
	// This emulates the relevant parts of t:cmdLine for Unix and Windows.
	switch cmdType {
	case CmdLineUnix:
		// matches tokens after each token that are added to evade detection
		a.evasionPatterns[evasionPattern] = ctx.rootContext.Configuration().Patterns.AntiEvasion.Unix
		// matches end of the command, someting like space, brace expansion or redirect must follow
		a.evasionPatterns[suffixPattern] = ctx.rootContext.Configuration().Patterns.AntiEvasionSuffix.Unix
		// Same as above but does not allow any white space as the next token.
		// This is useful for words like `python3`, where `python@` would
		// create too many false positives because it would match `python `.
		// This will match:
		//
		// python<<<foo
		// python2 foo
		//
		// It will _not_ match:
		// python foo
		a.evasionPatterns[suffixExpandedCommand] = ctx.rootContext.Configuration().Patterns.AntiEvasionNoSpaceSuffix.Unix
	case CmdLineWindows:
		// matches tokens after each token that are added to evade detection
		a.evasionPatterns[evasionPattern] = ctx.rootContext.Configuration().Patterns.AntiEvasion.Windows
		// matches end of the command, someting like space, brace expansion or redirect must follow
		a.evasionPatterns[suffixPattern] = ctx.rootContext.Configuration().Patterns.AntiEvasionSuffix.Windows
		// Same as above but does not allow any white space as the next token.
		// This is useful for words like `python3`, where `python@` would
		// create too many false positives because it would match `python `.
		// This will match:
		//
		// python,foo
		// python2 foo
		//
		// It will _not_ match:
		// python foo
		a.evasionPatterns[suffixExpandedCommand] = ctx.rootContext.Configuration().Patterns.AntiEvasionNoSpaceSuffix.Windows
	}

	return a
}

// ProcessLine applies the processors logic to a single line
func (c *CmdLine) ProcessLine(line string) error {
	if len(line) != 0 {
		processed := c.regexpStr(line)
		c.proc.lines = append(c.proc.lines, processed)
		logger.Trace().Msgf("cmdline in: %s", line)
		logger.Trace().Msgf("cmdline out: %s", processed)
	}
	return nil
}

// Complete is the class method
func (c *CmdLine) Complete() ([]string, error) {
	assembly, err := rassemble.Join(c.proc.lines)
	if err != nil {
		return nil, err
	}
	logger.Trace().Msgf("cmdLine Complete result: %v", assembly)
	return []string{assembly}, nil
}

// Consume applies the state of a nested processor
func (c *CmdLine) Consume(lines []string) error {
	for _, line := range lines {
		if err := c.ProcessLine(line); err != nil {
			return err
		}
	}
	return nil
}

// regexpStr converts a single line to regexp format, and insert anti-cmdline
// evasions between characters.
func (c *CmdLine) regexpStr(input string) string {
	logger.Trace().Msgf("regexpStr: %s", input)
	// By convention, if the line starts with ' char, copy the rest verbatim.
	if strings.Index(input, "'") == 0 {
		return input[1:]
	}

	result := bytes.Buffer{}
	for i, char := range []byte(input) {
		if i > 0 {
			result.WriteString(c.evasionPatterns[evasionPattern])
		}
		result.WriteString(c.regexpChar(char))
	}
	return result.String()
}

// regexpChar ensures that some special characters are escaped
func (c *CmdLine) regexpChar(char byte) string {
	logger.Trace().Msgf("regexpChar in: %v", char)

	chars := ""
	switch char {
	case '.':
		chars = "\\."
	case '-':
		chars = "\\-"
	case '@':
		chars = c.evasionPatterns[suffixPattern]
	case '~':
		chars = c.evasionPatterns[suffixExpandedCommand]
	default:
		chars = string(char)
	}
	logger.Trace().Msgf("regexpChar out: %s", chars)
	return strings.Replace(chars, " ", "\\s+", -1)
}

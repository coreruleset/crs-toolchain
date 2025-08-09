// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package processors

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"github.com/itchyny/rassemble-go"

	"github.com/coreruleset/crs-toolchain/v2/regex"
	"github.com/coreruleset/crs-toolchain/v2/utils"
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
		// matches end of the command, someting like space, brace expansion or redirect must follow (suffix marker `@`)
		a.evasionPatterns[suffixPattern] = ctx.rootContext.Configuration().Patterns.AntiEvasionSuffix.Unix
		// Same as above but does not allow any white space as the next token (suffix marker `~`).
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
	if len(line) == 0 {
		return nil
	}

	if err := c.validateLine(line); err != nil {
		return err
	}

	processed := c.expandWithPatterns(line)
	c.proc.lines = append(c.proc.lines, processed)
	logger.Trace().Msgf("cmdline in: %s", line)
	logger.Trace().Msgf("cmdline out: %s", processed)

	return nil
}

// Complete runs finalization steps of the processor
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

// validateLine returns an error when regex metacharacters `.` or `+` are
// found unescaped. Technically, we could append them to the previous output.
// However, the same files can be included using the include processor and there
// each line is interpreted as a regular expression. For this reason, we treat
// each line in cmdline process input as a regular expression, _but_ require that
// meta characters that can be part of a path name must be escaped.
// This is not a good solution, but a better solution requires rewriting the RCE rules
// in general.
func (c *CmdLine) validateLine(input string) error {
	for i, char := range input {
		switch char {
		case '.':
			fallthrough
		case '+':
			if !utils.IsEscaped(input, i) {
				return fmt.Errorf("found unescaped meta character `%s` in %s", string(char), input)
			}
		}
	}
	return nil
}

// expandWithPatterns inserts anti-cmdline evasions between characters and appends
// suffix patterns if required. Escape will be retained (i.e., backslashes will not be
// treated as characters to which an anti-evasion pattern needs to be appended).
func (c *CmdLine) expandWithPatterns(input string) string {
	logger.Trace().Msgf("regexpStr: %s", input)
	// By convention, if the line starts with ' char, copy the rest verbatim.
	if strings.Index(input, "'") == 0 {
		return input[1:]
	}

	result := bytes.Buffer{}
	strippedInput, suffix := c.computeSuffix(input)
	for i, char := range []byte(strippedInput) {
		if i > 0 {
			if !utils.IsEscaped(strippedInput, i) {
				// This char was preceded by a backslash.
				// Do not write evasion pattern.
				result.WriteString(c.evasionPatterns[evasionPattern])
			}
		}
		result.WriteByte(char)
	}
	if len(suffix) > 0 {
		result.WriteString(c.evasionPatterns[evasionPattern])
		result.WriteString(suffix)
	}
	return result.String()
}

// Computes the evasion suffix based on the presence of `@` or `~` at
// the end of the input. Returns the input without `@` or `~` or removes the
// backslash if the end of the input is an escape sequence of `\~` or `\@`.
// Returns the evasion suffix to append to the transformed input.
func (c *CmdLine) computeSuffix(input string) (string, string) {
	suffix := ""
	strippedInput := input
	length := len(input)
	if length < 2 {
		return strippedInput, suffix
	}

	isEscaped := regex.IsEscaped(input, length-1)
	if !isEscaped {
		switch input[length-1] {
		case '@':
			suffix = c.evasionPatterns[suffixPattern]
			strippedInput = input[:length-1]
		case '~':
			suffix = c.evasionPatterns[suffixExpandedCommand]
			strippedInput = input[:length-1]
		}

	} else {
		// remove the backslash
		switch input[length-1] {
		case '@':
			fallthrough
		case '~':
			strippedInput = input[:length-2] + string(input[length-1])
		}
	}

	return strippedInput, suffix
}

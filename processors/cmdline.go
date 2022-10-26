// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package processors

import (
	"bytes"
	"regexp"
	"strings"

	"github.com/itchyny/rassemble-go"
)

const (
	unix CmdlineType = iota
	windows
)
const (
	evasionPattern EvasionPatterns = iota
	suffixPattern
	suffixExpandedCommand
)

type CmdlineType int
type EvasionPatterns int

type Cmdline struct {
	proc            *Processor
	input           *regexp.Regexp
	output          *regexp.Regexp
	cmdType         CmdlineType
	evasionPatterns map[EvasionPatterns]string
}

// NewCmdline creates a new cmdline processor
func NewCmdline(ctx *Context, cmdType CmdlineType) *Cmdline {
	a := &Cmdline{
		proc:            NewProcessorWithContext(ctx),
		input:           regexp.MustCompile(AssembleInput),
		output:          regexp.MustCompile(AssembleOutput),
		cmdType:         cmdType,
		evasionPatterns: make(map[EvasionPatterns]string),
	}

	// Now add evasion patterns
	// We will insert these sequences between characters to prevent evasion.
	// This emulates the relevant parts of t:cmdLine.
	switch cmdType {
	case unix:
		a.evasionPatterns[evasionPattern] = `[\x5c'\"]*`
		// unix: "cat foo", "cat<foo", "cat>foo"
		a.evasionPatterns[suffixPattern] = `(?:\s|<|>).*`
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
		a.evasionPatterns[suffixExpandedCommand] = `(?:(?:<|>)|(?:[\w\d._-][\x5c'\"]*)+(?:\s|<|>)).*`
	case windows:
		a.evasionPatterns[evasionPattern] = `[\"\^]*`
		// windows: "more foo", "more,foo", "more;foo", "more.com", "more/e",
		// "more<foo", "more>foo"
		a.evasionPatterns[suffixPattern] = `(?:[\s,;]|\.|/|<|>).*`
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
		a.evasionPatterns[suffixExpandedCommand] = `(?:(?:[,;]|\.|/|<|>)|(?:[\w\d._-][\"\^]*)+(?:[\s,;]|\.|/|<|>)).*`
	}

	return a
}

// ProcessLine implements the line processor
func (c *Cmdline) ProcessLine(line string) {
	if len(line) != 0 {
		processed := c.regexpStr(line)
		c.proc.lines = append(c.proc.lines, processed)
		logger.Trace().Msgf("cmdline in: %s", line)
		logger.Trace().Msgf("cmdline out: %s", processed)
	}
}

// HasBody is a class method
func (c *Cmdline) HasBody() bool {
	// Empty method
	return true
}

// Complete is the class method
func (c *Cmdline) Complete() ([]string, error) {
	assembly, err := rassemble.Join(c.proc.lines)
	if err != nil {
		return nil, err
	}
	return []string{assembly}, nil
}

// regexpStr converts a single line to regexp format, and insert anti-cmdline
// evasions between characters.
func (c *Cmdline) regexpStr(input string) string {
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
func (c *Cmdline) regexpChar(char byte) string {
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

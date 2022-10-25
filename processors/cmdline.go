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
	Unix CmdlineType = iota
	Windows
	EvasionPattern EvasionPatterns = iota
	SuffixPattern
	SuffixExpandedCommand
)

type CmdlineType int
type EvasionPatterns int

type Cmdline struct {
	proc             *Processor
	input            *regexp.Regexp
	output           *regexp.Regexp
	cmdType          CmdlineType
	evasion_patterns map[EvasionPatterns]string
}

// NewCmdline creates a new cmdline processor
func NewCmdline(ctx *Context, cmdType CmdlineType) *Cmdline {
	a := &Cmdline{
		proc:             NewProcessorWithContext(ctx),
		input:            regexp.MustCompile(AssembleInput),
		output:           regexp.MustCompile(AssembleOutput),
		cmdType:          cmdType,
		evasion_patterns: make(map[EvasionPatterns]string),
	}

	// Now add evasion patterns
	// We will insert these sequences between characters to prevent evasion.
	// This emulates the relevant parts of t:cmdLine.
	switch cmdType {
	case Unix:
		a.evasion_patterns[EvasionPattern] = `[\x5c'\"]*`
		// Unix: "cat foo", "cat<foo", "cat>foo"
		a.evasion_patterns[SuffixPattern] = `(?:\s|<|>).*`
		// Same as above but does not allow any white space as the next token.
		// This is useful for thing like `python3`, where `python@` would
		// create too many false positives because it would match `python `.
		// This will match:
		//
		// python<<<foo
		// python2 foo
		//
		// It will _not_ match:
		// python foo
		a.evasion_patterns[SuffixExpandedCommand] = `(?:(?:<|>)|(?:[\w\d._-][\x5c'\"]*)+(?:\s|<|>)).*`
	case Windows:
		a.evasion_patterns[EvasionPattern] = `[\"\^]*`
		// Windows: "more foo", "more,foo", "more;foo", "more.com", "more/e",
		// "more<foo", "more>foo"
		a.evasion_patterns[SuffixPattern] = `(?:[\s,;]|\.|/|<|>).*`
		// Same as above but does not allow any white space as the next token.
		// This is useful for thing like `python3`, where `python@` would
		// create too many false positives because it would match `python `.
		// This will match:
		//
		// python,foo
		// python2 foo
		//
		// It will _not_ match:
		// python foo
		a.evasion_patterns[SuffixExpandedCommand] = `(?:(?:[,;]|\.|/|<|>)|(?:[\w\d._-][\"\^]*)+(?:[\s,;]|\.|/|<|>)).*`
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
	// By convention, if the line starts with ' char, copy the rest verbatim.
	if strings.Index(input, "'") == 0 {
		return input[1:]
	}
	// If this line is a comment, return as is
	if c.proc.commentRegex.MatchString(input) {
		return input
	}

	result := bytes.Buffer{}
	for i, char := range []byte(input) {
		if i > 0 {
			result.WriteString(c.evasion_patterns[EvasionPattern])
		}
		result.WriteString(c.regexpChar(char))
	}
	return result.String()
}

// regexpChar ensures that some special characters are escaped
func (c *Cmdline) regexpChar(char byte) string {
	chars := ""
	switch char {
	case '.':
		chars = "\\."
	case '-':
		chars = "\\."
	case '@':
		chars = c.evasion_patterns[SuffixPattern]
	case '~':
		chars = c.evasion_patterns[SuffixExpandedCommand]
	}
	return strings.Replace(chars, " ", "\\s+", -1)
}

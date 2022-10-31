// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package processors

import (
	"bytes"
	"errors"
	"regexp"
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
	input           *regexp.Regexp
	output          *regexp.Regexp
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
		proc:            NewProcessorWithContext(ctx),
		input:           regexp.MustCompile(AssembleInput),
		output:          regexp.MustCompile(AssembleOutput),
		cmdType:         cmdType,
		evasionPatterns: make(map[EvasionPatterns]string),
	}

	// Now add evasion patterns
	// We will insert these sequences between characters to prevent evasion.
	// This emulates the relevant parts of t:cmdLine for Unix and Windows.
	//
	// The Unix evasion patterns, were extended per decision in https://github.com/coreruleset/coreruleset/issues/2632.
	switch cmdType {
	case CmdLineUnix:
		a.evasionPatterns[evasionPattern] = `[\x5c'\"\[]*(?:\$[a-z0-9_@?!#{*-]*)?(?:\x5c)?`
		// CmdLineUnix: "cat foo", "cat<foo", "cat>foo"
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
		a.evasionPatterns[suffixExpandedCommand] = `(?:(?:<|>)|(?:[\w\d._-][\x5c'\"\[]*(?:\$[a-z0-9_@?!#{*-]*)?(?:\x5c)?)+(?:\s|<|>)).*`
	case CmdLineWindows:
		a.evasionPatterns[evasionPattern] = `[\"\^]*`
		// CmdLineWindows: "more foo", "more,foo", "more;foo", "more.com", "more/e",
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
func (c *CmdLine) ProcessLine(line string) {
	if len(line) != 0 {
		processed := c.regexpStr(line)
		c.proc.lines = append(c.proc.lines, processed)
		logger.Trace().Msgf("cmdline in: %s", line)
		logger.Trace().Msgf("cmdline out: %s", processed)
	}
}

// HasBody is a class method
func (c *CmdLine) HasBody() bool {
	// Empty method
	return true
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

func (c *CmdLine) Consume(lines []string) {
	for _, line := range lines {
		c.ProcessLine(line)
	}
}

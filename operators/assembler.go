// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"bufio"
	"bytes"
	"fmt"
	"regexp"
	"strings"

	"github.com/theseion/crs-toolchain/v2/parser"
	"github.com/theseion/crs-toolchain/v2/processors"
)

type Indent int

const (
	commentRegexPrefix = `\s*##!`
	// prefix, suffix, flags, block start block end
	specialCommentMarkers          = "^$+><="
	preprocessorStartRegexTemplate = `%s}>\s*(.*)`
	preprocessorEndRegexTemplate   = "%s}<"
	simpleCommentRegexTemplate     = "%s}[^%s]"
)

var regexes = struct {
	preprocessorStart regexp.Regexp
	preprocessorEnd   regexp.Regexp
	simpleComment     regexp.Regexp
}{
	preprocessorStart: *regexp.MustCompile(fmt.Sprintf(preprocessorStartRegexTemplate, commentRegexPrefix)),
	preprocessorEnd:   *regexp.MustCompile(fmt.Sprintf(preprocessorEndRegexTemplate, commentRegexPrefix)),
	simpleComment:     *regexp.MustCompile(fmt.Sprintf(simpleCommentRegexTemplate, commentRegexPrefix, specialCommentMarkers)),
}

// Create the operator stack
var operatorStack = []OperatorStack{}

func NewAssembler(ctx *processors.Context) *Operator {
	a := &Operator{
		name:    "assemble",
		details: make(map[string]string),
		lines:   []string{},
		ctx:     ctx,
		stats:   NewStats(),
	}
	return a
}

func (a *Assembler) Run(input string) (string, error) {
	logger.Trace().Msg("Starting assembler")
	parser := parser.NewParser(a.ctx, strings.NewReader(input))
	lines, _ := parser.Parse()
	logger.Trace().Msgf("Parsed lines: %v", lines)
	return a.Assemble(lines)
}

func (a *Assembler) Assemble(input *bytes.Buffer) (string, error) {
	fileScanner := bufio.NewScanner(bytes.NewReader(input.Bytes()))
	fileScanner.Split(bufio.ScanLines)
	var text string

	for fileScanner.Scan() {
		line := fileScanner.Text()
		text = "" // empty text each iteration
		logger.Trace().Msgf("parsing line: %q", line)
	}

	return text, nil
}

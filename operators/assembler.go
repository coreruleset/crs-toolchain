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

type Assembler Operator

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

func NewAssembler(ctx *processors.Context) *Assembler {
	a := &Assembler{
		ctx:   ctx,
		stats: NewStats(),
	}
	return a
}

func (a *Assembler) Preprocess(reader *bufio.Reader) (string, error) {
	//TODO: Implement
	return "TODO", nil
}

func (a *Assembler) Run(input string) (string, error) {
	logger.Trace().Msg("Starting assembler")
	parser := parser.NewParser(a.ctx, strings.NewReader(input))
	lines, _ := parser.Parse()
	logger.Trace().Msgf("Parsed lines: %v", lines)
	return a.run(lines)
}

func (a *Assembler) run(input *bytes.Buffer) (string, error) {
	reader := bufio.NewReader(bytes.NewReader(input.Bytes()))
	return a.Preprocess(reader)
}

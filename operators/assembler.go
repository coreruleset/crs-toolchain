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
	comment_regex_prefix = `\s*##!`
	// prefix, suffix, flags, block start block end
	special_comment_markers           = "^$+><="
	preprocessor_start_regex_template = `%s}>\s*(.*)`
	preprocessor_end_regex_template   = "%s}<"
	simple_comment_regex_template     = "%s}[^%s]"
)

var regexes = struct {
	preprocessor_start regexp.Regexp
	preprocessor_end   regexp.Regexp
	simple_comment     regexp.Regexp
}{
	preprocessor_start: *regexp.MustCompile(fmt.Sprintf(preprocessor_start_regex_template, comment_regex_prefix)),
	preprocessor_end:   *regexp.MustCompile(fmt.Sprintf(preprocessor_end_regex_template, comment_regex_prefix)),
	simple_comment:     *regexp.MustCompile(fmt.Sprintf(simple_comment_regex_template, comment_regex_prefix, special_comment_markers)),
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
	a.run(lines)
}

func (a *Assembler) run(input *bytes.Buffer) (string, error) {
	reader := bufio.NewReader(bytes.NewReader(input.Bytes()))
	a.Preprocess(reader)
}

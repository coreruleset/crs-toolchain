// Copyright 2023 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"bytes"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/coreruleset/crs-toolchain/v2/context"
	"github.com/coreruleset/crs-toolchain/v2/regex/processors"
)

type parserDefinitionTestSuite struct {
	suite.Suite
	rootDir string
	ctx     *processors.Context
	reader  io.Reader
}

func TestParserDefinitionsTestSuite(t *testing.T) {
	suite.Run(t, new(parserDefinitionTestSuite))
}

func (s *parserDefinitionTestSuite) SetupSuite() {
	s.rootDir = s.T().TempDir()
	rootContext := context.New(filepath.Dir(s.rootDir), "toolchain.yaml")
	s.ctx = processors.NewContext(rootContext)
	s.reader = strings.NewReader("##!> define this-is-a-text [a-zA-J]+8\n" +
		"##!> define this-is-another-text [0-9](pine|apple)\n" +
		"{{this-is-a-text}} to see if definitions work.\n" +
		"Second text for {{this-is-another-text}}.\n")
}

func (s *parserDefinitionTestSuite) TestParserDefinition_BasicTest() {
	parser := NewParser(s.ctx, s.reader)
	actual, _ := parser.Parse(false)
	expected := bytes.NewBufferString("[a-zA-J]+8 to see if definitions work.\nSecond text for [0-9](pine|apple).\n")

	s.Greater(len(parser.variables), 0)
	s.Equal(parser.variables["this-is-a-text"], "[a-zA-J]+8", "failed to found definition variables in map")
	s.Equal(parser.variables["this-is-another-text"], "[0-9](pine|apple)", "failed to found definition variables in map")
	s.Equal(expected.String(), actual.String())
}

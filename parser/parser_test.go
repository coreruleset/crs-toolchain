// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/suite"
)

type parserTestSuite struct {
	suite.Suite
	reader io.Reader
}

func (s *parserTestSuite) SetupTest() {
	s.reader = strings.NewReader("##! This is a comment.\n##! This is another line.\n")
}

func TestRunParserTestSuite(t *testing.T) {
	suite.Run(t, new(parserTestSuite))
	suite.Run(t, new(parserIncludeTestSuite))
}

func (s *parserTestSuite) TestParser_NewParser() {
	expected := &Parser{
		src:       s.reader,
		dest:      &bytes.Buffer{},
		variables: make(map[string]string),
		patterns: map[string]*regexp.Regexp{
			IncludePatternName:  regexp.MustCompile(IncludePattern),
			TemplatePatternName: regexp.MustCompile(TemplatePattern),
		},
	}
	actual := NewParser(s.reader)

	s.Equal(expected, actual)
}

func (s *parserTestSuite) TestParser_ParseTwoComments() {
	parser := NewParser(s.reader)

	actual, n := parser.Parse()
	expected := bytes.NewBufferString("##! This is a comment.\n##! This is another line.\n")

	s.Equal(expected.String(), actual.String())
	s.Equal(expected.Len(), n)
}

type parserIncludeTestSuite struct {
	suite.Suite
	reader      io.Reader
	includeFile *os.File
}

func (s *parserIncludeTestSuite) SetupSuite() {
	var err error
	s.includeFile, err = os.CreateTemp(os.TempDir(), "test.data")
	s.NoError(err, "couldn't create %s file", s.includeFile.Name())
	n, err := s.includeFile.WriteString("This data comes from the included file.\n")
	s.NoError(err, "writing temp include file failed")
	s.Equal(len("This data comes from the included file.\n"), n)
	s.reader = strings.NewReader(fmt.Sprintf("##!> include %s\n##! This is a comment line.\n", s.includeFile.Name()))
}

func (s *parserIncludeTestSuite) TearDownSuite() {
	s.includeFile.Close()
	os.Remove("test.data")
}

func (s *parserIncludeTestSuite) TestParserInclude_FromFile() {
	parser := NewParser(s.reader)
	actual, n := parser.Parse()
	expected := bytes.NewBufferString("This data comes from the included file.\n##! This is a comment line.\n")

	s.Equal(expected.String(), actual.String())
	s.Equal(expected.Len(), n)
}

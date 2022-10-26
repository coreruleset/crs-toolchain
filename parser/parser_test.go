// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"bytes"
	"fmt"
	"github.com/theseion/crs-toolchain/v2/processors"
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
	suite.Run(t, new(parserMultiIncludeTestSuite))
	suite.Run(t, new(parserTemplateTestSuite))
	suite.Run(t, new(parserIncludeWithTemplates))
}

func (s *parserTestSuite) TestParser_NewParser() {
	expected := &Parser{
		ctx:       processors.NewContext(),
		src:       s.reader,
		dest:      &bytes.Buffer{},
		variables: make(map[string]string),
		patterns: map[string]*regexp.Regexp{
			IncludePatternName:  regexp.MustCompile(IncludePattern),
			TemplatePatternName: regexp.MustCompile(TemplatePattern),
		},
	}
	actual := NewParser(processors.NewContext(), s.reader)

	s.Equal(expected, actual)
}

func (s *parserTestSuite) TestParser_ParseTwoComments() {
	parser := NewParser(processors.NewContext(), s.reader)

	actual, n := parser.Parse()
	expected := bytes.NewBufferString("##! This is a comment.\n##! This is another line.\n")

	s.Equal(expected.String(), actual.String())
	s.Equal(expected.Len(), n)
}

type parserIncludeTestSuite struct {
	suite.Suite
	ctx           *processors.Context
	reader        io.Reader
	testDirectory string
	includeFile   *os.File
}

func (s *parserIncludeTestSuite) SetupSuite() {
	var err error
	s.testDirectory, err = os.MkdirTemp("", "include-tests")
	s.NoError(err)
	s.ctx = processors.NewContextForDir(s.testDirectory)
	s.includeFile, err = os.CreateTemp(s.testDirectory, "test.data")
	s.NoError(err, "couldn't create %s file", s.includeFile.Name())
	n, err := s.includeFile.WriteString("This data comes from the included file.\n")
	s.NoError(err, "writing temp include file failed")
	s.Equal(len("This data comes from the included file.\n"), n)
	s.reader = strings.NewReader(fmt.Sprintf("##!> include %s\n##! This is a comment line.\n", s.includeFile.Name()))
}

func (s *parserIncludeTestSuite) TearDownSuite() {
	s.NoError(s.includeFile.Close())
	s.NoError(os.RemoveAll(s.testDirectory))
}

func (s *parserIncludeTestSuite) TestParserInclude_FromFile() {
	parser := NewParser(s.ctx, s.reader)
	actual, n := parser.Parse()
	expected := bytes.NewBufferString("This data comes from the included file.\n##! This is a comment line.\n")

	s.Equal(expected.String(), actual.String())
	s.Equal(expected.Len(), n)
}

//TODO: add test for relative include based on context

// Test Suite to perform multiple inclusions

type parserMultiIncludeTestSuite struct {
	suite.Suite
	ctx         *processors.Context
	reader      io.Reader
	includeFile []*os.File
}

func (s *parserMultiIncludeTestSuite) SetupSuite() {
	tmpdir := os.TempDir()
	s.ctx = processors.NewContextForDir(tmpdir)
	for i := 0; i < 4; i++ {
		file, err := os.CreateTemp(tmpdir, "multi-include.data")
		s.NoError(err, "couldn't create %s file", file.Name())
		if i == 0 {
			// Only the initial include goes to the reader
			s.reader = strings.NewReader(fmt.Sprintf("##!> include %s\n##! This is comment %d.\n", file.Name(), i))
		}
		s.includeFile = append(s.includeFile, file)
		// Write to file i-1
		if i > 0 {
			_, err := s.includeFile[i-1].WriteString(fmt.Sprintf("##!> include %s\n##! This is comment %d.\n", file.Name(), i))
			s.NoError(err, "writing temp include file failed")
		}
	}
}

func (s *parserMultiIncludeTestSuite) TearDownSuite() {
	for i := 0; i < 4; i++ {
		s.NoError(s.includeFile[i].Close())
		s.NoError(os.Remove(s.includeFile[i].Name()))
	}
}

func (s *parserMultiIncludeTestSuite) TestParserMultiInclude_FromMultiFile() {
	parser := NewParser(s.ctx, s.reader)
	actual, n := parser.Parse()
	expected := bytes.NewBufferString("##! This is comment 3.\n##! This is comment 2.\n##! This is comment 1.\n##! This is comment 0.\n")

	s.Equal(expected.String(), actual.String())
	s.Equal(expected.Len(), n)
}

// Templates test suite
type parserTemplateTestSuite struct {
	suite.Suite
	ctx    *processors.Context
	reader io.Reader
}

func (s *parserTemplateTestSuite) SetupSuite() {
	s.ctx = processors.NewContext()
	s.reader = strings.NewReader("##!> template this-is-a-text [a-zA-J]+8\n" +
		"##!> template this-is-another-text [0-9](pine|apple)\n" +
		"{{this-is-a-text}} to see if templates work.\n" +
		"Second text for {{this-is-another-text}}.\n")
}

func (s *parserTemplateTestSuite) TestParserTemplate_BasicTest() {
	parser := NewParser(s.ctx, s.reader)
	actual, _ := parser.Parse()
	expected := bytes.NewBufferString("[a-zA-J]+8 to see if templates work.\nSecond text for [0-9](pine|apple).\n")

	s.Greater(len(parser.variables), 0)
	s.Equal(parser.variables["this-is-a-text"], "[a-zA-J]+8", "failed to found template variables in map")
	s.Equal(parser.variables["this-is-another-text"], "[0-9](pine|apple)", "failed to found template variables in map")
	s.Equal(expected.String(), actual.String())
}

// Templates test suite
type parserIncludeWithTemplates struct {
	suite.Suite
	ctx         *processors.Context
	reader      io.Reader
	includeFile []*os.File
}

func (s *parserIncludeWithTemplates) SetupSuite() {
	tmpdir := os.TempDir()
	s.ctx = processors.NewContextForDir(tmpdir)
	for i := 0; i < 4; i++ {
		file, err := os.CreateTemp(tmpdir, "multi-templates.data")
		s.NoError(err, "couldn't create %s file", file.Name())
		if i == 0 {
			// Only the initial include goes to the reader
			s.reader = strings.NewReader(fmt.Sprintf(
				"##!> include %s\n"+
					"##!> template this-is-a-text [a-zA-J]+8\n"+
					"##!> template this-is-another-text [0-9](pine|apple)\n"+
					"{{this-is-a-text}} to see if templates work.\n"+
					"Second text for {{this-is-another-text}}.\n", file.Name()))
		}
		s.includeFile = append(s.includeFile, file)
		// Write to file i-1
		if i > 0 {
			_, err := s.includeFile[i-1].WriteString(
				fmt.Sprintf(
					"##!> include %s\n"+
						"##! This is comment %d.\n"+
						"{{this-is-a-text}} to see if templates work when included\n", file.Name(), i))
			s.NoError(err, "writing temp include file failed")
		}
	}
}

func (s *parserIncludeWithTemplates) TestParser_IncludeWithTemplates() {
	parser := NewParser(s.ctx, s.reader)
	actual, _ := parser.Parse()
	expected := bytes.NewBufferString(
		"##! This is comment 3.\n" +
			"[a-zA-J]+8 to see if templates work when included\n" +
			"##! This is comment 2.\n" +
			"[a-zA-J]+8 to see if templates work when included\n" +
			"##! This is comment 1.\n" +
			"[a-zA-J]+8 to see if templates work when included\n" +
			"[a-zA-J]+8 to see if templates work.\n" +
			"Second text for [0-9](pine|apple).\n")

	s.NotEmpty(parser.variables)
	s.Equal(parser.variables["this-is-a-text"], "[a-zA-J]+8", "failed to found template variables in map")
	s.Equal(parser.variables["this-is-another-text"], "[0-9](pine|apple)", "failed to found template variables in map")
	s.Equal(expected.String(), actual.String())
}

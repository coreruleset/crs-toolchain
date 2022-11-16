// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/theseion/crs-toolchain/v2/regex"
	"github.com/theseion/crs-toolchain/v2/regex/processors"
)

type parserTestSuite struct {
	suite.Suite
	reader io.Reader
}

func TestRunParserTestSuite(t *testing.T) {
	suite.Run(t, new(parserTestSuite))
	suite.Run(t, new(parserIncludeTestSuite))
	suite.Run(t, new(parserMultiIncludeTestSuite))
	suite.Run(t, new(parserDefinitionTestSuite))
	suite.Run(t, new(parserIncludeWithDefinitions))
}

func (s *parserTestSuite) TestParser_NewParser() {
	expected := &Parser{
		ctx:       processors.NewContext(os.TempDir()),
		src:       s.reader,
		dest:      &bytes.Buffer{},
		Flags:     make(map[rune]bool),
		Prefixes:  []string{},
		Suffixes:  []string{},
		variables: make(map[string]string),
		patterns: map[string]*regexp.Regexp{
			includePatternName:    regex.IncludeRegex,
			definitionPatternName: regex.DefinitionRegex,
			commentPatternName:    regex.CommentRegex,
			flagsPatternName:      regex.FlagsRegex,
			prefixPatternName:     regex.PrefixRegex,
			suffixPatternName:     regex.SuffixRegex,
		},
	}
	actual := NewParser(processors.NewContext(os.TempDir()), s.reader)

	s.Equal(expected, actual)
}

func (s *parserTestSuite) TestParser_ParseTwoComments() {
	reader := strings.NewReader("##! This is a comment.\n##! This is another line.\n")
	parser := NewParser(processors.NewContext(os.TempDir()), reader)

	actual, n := parser.Parse(false)
	expected := bytes.NewBufferString("")

	s.Equal(expected.String(), actual.String())
	s.Len(expected.String(), n)
}

func (s *parserTestSuite) TestIgnoresEmptyLines() {
	contents := "some line\n\nanother line"
	reader := strings.NewReader(contents)
	parser := NewParser(processors.NewContext(os.TempDir()), reader)
	actual, n := parser.Parse(false)

	expected := "some line\nanother line\n"
	s.Equal(expected, actual.String())
	s.Len(expected, n)
}

func (s *parserTestSuite) TestPanicsOnUnrecognizedFlag() {
	contents := "##!+ flag"
	reader := strings.NewReader(contents)
	parser := NewParser(processors.NewContext(os.TempDir()), reader)

	s.PanicsWithValue("flag 'f' is not supported", func() { parser.Parse(false) }, "should panic because flags are not supported")

}

type parserIncludeTestSuite struct {
	suite.Suite
	ctx         *processors.Context
	reader      io.Reader
	tempDir     string
	includeDir  string
	includeFile *os.File
}

func (s *parserIncludeTestSuite) SetupSuite() {
	var err error
	s.tempDir, err = os.MkdirTemp("", "include-tests")
	s.NoError(err)

	s.includeDir = path.Join(s.tempDir, "util", "regexp-assemble", "data", "include")
	err = os.MkdirAll(s.includeDir, fs.ModePerm)
	s.NoError(err)

	s.ctx = processors.NewContext(s.tempDir)
	s.includeFile, err = os.Create(path.Join(s.includeDir, "test.data"))
	s.NoError(err, "couldn't create %s file", s.includeFile.Name())

	n, err := s.includeFile.WriteString("This data comes from the included file.\n")
	s.NoError(err, "writing temp include file failed")

	s.Equal(len("This data comes from the included file.\n"), n)
	s.reader = strings.NewReader(fmt.Sprintf("##!> include %s\n##! This is a comment line.\n", s.includeFile.Name()))
}

func (s *parserIncludeTestSuite) TearDownSuite() {
	s.NoError(s.includeFile.Close())
	s.NoError(os.RemoveAll(s.tempDir))
}

func (s *parserIncludeTestSuite) TestParserInclude_FromFile() {
	parser := NewParser(s.ctx, s.reader)
	actual, n := parser.Parse(false)
	expected := bytes.NewBufferString("This data comes from the included file.\n")

	s.Equal(expected.String(), actual.String())
	s.Equal(expected.Len(), n)
}

// Test Suite to perform multiple inclusions
type parserMultiIncludeTestSuite struct {
	suite.Suite
	ctx         *processors.Context
	reader      io.Reader
	tempDir     string
	includeDir  string
	includeFile []*os.File
}

func (s *parserMultiIncludeTestSuite) SetupSuite() {
	tempDir, err := os.MkdirTemp("", "include-multi-tests")
	s.NoError(err)
	s.tempDir = tempDir

	s.includeDir = path.Join(s.tempDir, "util", "regexp-assemble", "data", "include")
	err = os.MkdirAll(s.includeDir, fs.ModePerm)
	s.NoError(err)

	s.ctx = processors.NewContext(s.tempDir)
	for i := 0; i < 4; i++ {
		file, err := os.Create(path.Join(s.includeDir, fmt.Sprintf("multi-include-%d.data", i)))
		s.NoError(err, "couldn't create %s file", file.Name())
		if i == 0 {
			// Only the initial include goes to the reader
			s.reader = strings.NewReader(fmt.Sprintf("##!> include %s\nThis is comment %d.\n", file.Name(), i))
		}
		s.includeFile = append(s.includeFile, file)
		// Write to file i-1
		if i > 0 {
			_, err := s.includeFile[i-1].WriteString(fmt.Sprintf("##!> include %s\nThis is comment %d.\n", file.Name(), i))
			s.NoError(err, "writing temp include file failed")
		}
	}
}

func (s *parserMultiIncludeTestSuite) TearDownSuite() {
	err := os.RemoveAll(s.tempDir)
	s.NoError(err)
}

func (s *parserMultiIncludeTestSuite) TestParserMultiInclude_FromMultiFile() {
	parser := NewParser(s.ctx, s.reader)
	actual, n := parser.Parse(false)
	expected := bytes.NewBufferString("This is comment 3.\nThis is comment 2.\nThis is comment 1.\nThis is comment 0.\n")

	s.Equal(expected.String(), actual.String())
	s.Equal(expected.Len(), n)
}

// Definitions test suite
type parserDefinitionTestSuite struct {
	suite.Suite
	ctx    *processors.Context
	reader io.Reader
}

func (s *parserDefinitionTestSuite) SetupSuite() {
	s.ctx = processors.NewContext(os.TempDir())
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

// Definitions test suite
type parserIncludeWithDefinitions struct {
	suite.Suite
	ctx         *processors.Context
	reader      io.Reader
	tempDir     string
	includeDir  string
	includeFile []*os.File
}

func (s *parserIncludeWithDefinitions) SetupSuite() {
	tempDir, err := os.MkdirTemp("", "include-multi-tests")
	s.NoError(err)
	s.tempDir = tempDir

	s.includeDir = path.Join(s.tempDir, "util", "regexp-assemble", "data", "include")
	err = os.MkdirAll(s.includeDir, fs.ModePerm)
	s.NoError(err)

	s.ctx = processors.NewContext(s.tempDir)
	for i := 0; i < 4; i++ {
		file, err := os.Create(path.Join(s.tempDir, fmt.Sprintf("multi-definitions-%d.data", i)))
		s.NoError(err, "couldn't create %s file", file.Name())
		if i == 0 {
			// Only the initial include goes to the reader
			s.reader = strings.NewReader(fmt.Sprintf(
				"##!> include %s\n"+
					"##!> define this-is-a-text [a-zA-J]+8\n"+
					"##!> define this-is-another-text [0-9](pine|apple)\n"+
					"{{this-is-a-text}} to see if definitions work.\n"+
					"Second text for {{this-is-another-text}}.\n", file.Name()))
		}
		s.includeFile = append(s.includeFile, file)
		// Write to file i-1
		if i > 0 {
			_, err := s.includeFile[i-1].WriteString(
				fmt.Sprintf(
					"##!> include %s\n"+
						"This is comment %d.\n"+
						"{{this-is-a-text}} to see if definitions work when included\n", file.Name(), i))
			s.NoError(err, "writing temp include file failed")
		}
	}
}

func (s *parserIncludeWithDefinitions) TestParser_IncludeWithDefinitions() {
	parser := NewParser(s.ctx, s.reader)
	actual, _ := parser.Parse(false)
	expected := bytes.NewBufferString(
		"This is comment 3.\n" +
			"[a-zA-J]+8 to see if definitions work when included\n" +
			"This is comment 2.\n" +
			"[a-zA-J]+8 to see if definitions work when included\n" +
			"This is comment 1.\n" +
			"[a-zA-J]+8 to see if definitions work when included\n" +
			"[a-zA-J]+8 to see if definitions work.\n" +
			"Second text for [0-9](pine|apple).\n")

	s.NotEmpty(parser.variables)
	s.Equal(parser.variables["this-is-a-text"], "[a-zA-J]+8", "failed to found definition variables in map")
	s.Equal(parser.variables["this-is-another-text"], "[0-9](pine|apple)", "failed to found definition variables in map")
	s.Equal(expected.String(), actual.String())
}

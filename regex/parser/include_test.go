// Copyright 2023 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/coreruleset/crs-toolchain/v2/context"
	"github.com/coreruleset/crs-toolchain/v2/regex/processors"
)

type parserIncludeTestSuite struct {
	suite.Suite
	rootDir     string
	ctx         *processors.Context
	reader      io.Reader
	tempDir     string
	includeDir  string
	includeFile *os.File
}

func (s *parserIncludeTestSuite) writeDataFile(includeContents string, dataContents string) {
	_, err := s.includeFile.WriteString(includeContents)
	s.Require().NoError(err, "writing temp include file failed")

	s.reader = strings.NewReader(fmt.Sprintf("##!> include %s\n%s", s.includeFile.Name(), dataContents))
}

func TestRunParserIncludeTestSuite(t *testing.T) {
	suite.Run(t, new(parserIncludeTestSuite))
}

func (s *parserIncludeTestSuite) SetupTest() {
	s.rootDir = s.T().TempDir()
	s.includeDir = path.Join(s.rootDir, "regex-assembly", "include")
	err := os.MkdirAll(s.includeDir, fs.ModePerm)
	s.Require().NoError(err)

	rootContext := context.New(s.rootDir, "toolchain.yaml")
	s.ctx = processors.NewContext(rootContext)
	s.includeFile, err = os.Create(path.Join(s.includeDir, "test.ra"))
	s.Require().NoError(err, "couldn't create %s file", s.includeFile.Name())
}

func (s *parserIncludeTestSuite) TearDownTest() {
	s.Require().NoError(s.includeFile.Close())
	s.Require().NoError(os.RemoveAll(s.tempDir))
}

func (s *parserIncludeTestSuite) TestParserInclude_FromFile() {
	s.writeDataFile("This data comes from the include file.\n", "##!This is a comment\n")
	parser := NewParser(s.ctx, s.reader)
	actual := parser.Parse(false)
	expected := bytes.NewBufferString("This data comes from the include file.\n")

	s.Equal(expected.String(), actual.String())
}

func (s *parserIncludeTestSuite) TestParserInclude_ReportsLineTooLong() {
	s.writeDataFile(strings.Repeat("a", 2*MaxLineSize)+"\n", "data\n")
	parser := NewParser(s.ctx, s.reader)

	parser.Parse(false)

	s.Require().ErrorIs(parser.Err(), bufio.ErrTooLong)
}

func (s *parserIncludeTestSuite) TestParserInclude_ReportsMissingFile() {
	parser := NewParser(s.ctx, strings.NewReader("##!> include does-not-exist\n"))

	parser.Parse(false)

	s.Require().ErrorIs(parser.Err(), os.ErrNotExist)
}

func (s *parserIncludeTestSuite) TestParserInclude_AcceptsLongLine() {
	line := strings.Repeat("a", 100*1024)
	s.writeDataFile(line+"\n", "data\n")
	parser := NewParser(s.ctx, s.reader)

	actual := parser.Parse(false)

	s.Require().NoError(parser.Err())
	s.Equal(line+"\ndata\n", actual.String())
}

func (s *parserIncludeTestSuite) TestParserInclude_Prefixes() {
	s.writeDataFile(`##!^ prefix1
##!^ prefix2
included regex`, "data regex")
	parser := NewParser(s.ctx, s.reader)
	actual := parser.Parse(false)
	expected := bytes.NewBufferString(`##!> assemble
prefix1
##!=>
prefix2
##!=>
included regex
##!<
data regex
`)
	s.Equal(expected.String(), actual.String())
}

func (s *parserIncludeTestSuite) TestParserInclude_Suffixes() {
	s.writeDataFile(`##!$ suffix1
##!$ suffix2
included regex`, "data regex")
	parser := NewParser(s.ctx, s.reader)
	actual := parser.Parse(false)
	expected := bytes.NewBufferString(`##!> assemble
included regex
##!=>
suffix1
##!=>
suffix2
##!=>
##!<
data regex
`)

	s.Equal(expected.String(), actual.String())
}

func (s *parserIncludeTestSuite) TestParserInclude_FlagsPrefixesSuffixes() {
	s.writeDataFile(`##!$ suffix1
##!$ suffix2
##!^ prefix1
##!^ prefix2
included regex`, "data regex")
	parser := NewParser(s.ctx, s.reader)
	actual := parser.Parse(false)
	expected := bytes.NewBufferString(`##!> assemble
prefix1
##!=>
prefix2
##!=>
included regex
##!=>
suffix1
##!=>
suffix2
##!=>
##!<
data regex
`)

	s.Equal(expected.String(), actual.String())
}

func (s *parserIncludeTestSuite) TestParserInclude_SuffixReplacements() {
	_, err := s.includeFile.WriteString(`no suffix1
suffix with@
suffix with~
no suffix 2`)
	s.Require().NoError(err, "writing temp include file failed")

	s.reader = strings.NewReader(fmt.Sprintf(
		"##!> include %s -- %s %s %s %s", s.includeFile.Name(),
		"@", `[\s><]`,
		"~", `[^\s]`))
	parser := NewParser(s.ctx, s.reader)
	actual := parser.Parse(false)
	expected := bytes.NewBufferString(`no suffix1
suffix with[\s><]
suffix with[^\s]
no suffix 2
`)

	s.Equal(expected.String(), actual.String())
}

func (s *parserIncludeTestSuite) TestParserInclude_SuffixReplacements_WithBadSpacing() {
	_, err := s.includeFile.WriteString(`no suffix1
suffix with@
suffix with~
no suffix 2`)
	s.Require().NoError(err, "writing temp include file failed")

	s.reader = strings.NewReader(fmt.Sprintf(
		"##!> include %s--   %s %s %s %s", s.includeFile.Name(),
		"  @", `[\s><]  `,
		"~   ", `   [^\s]`))
	parser := NewParser(s.ctx, s.reader)
	actual := parser.Parse(false)
	expected := bytes.NewBufferString(`no suffix1
suffix with[\s><]
suffix with[^\s]
no suffix 2
`)

	s.Equal(expected.String(), actual.String())
}

func (s *parserIncludeTestSuite) TestParserInclude_SuffixReplacements_WithEmptyString() {
	_, err := s.includeFile.WriteString(`no suffix1
suffix with@
suffix with~
no suffix 2`)
	s.Require().NoError(err, "writing temp include file failed")

	s.reader = strings.NewReader(fmt.Sprintf(
		"##!> include %s -- %s %s %s %s", s.includeFile.Name(),
		"@", `""`,
		"~", `""`))
	parser := NewParser(s.ctx, s.reader)
	actual := parser.Parse(false)
	expected := bytes.NewBufferString(`no suffix1
suffix with
suffix with
no suffix 2
`)

	s.Equal(expected.String(), actual.String())
}

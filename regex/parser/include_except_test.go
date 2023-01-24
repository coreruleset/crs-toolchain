// Copyright 2023 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/suite"

	"github.com/coreruleset/crs-toolchain/context"
	"github.com/coreruleset/crs-toolchain/regex/processors"
)

type parserIncludeExceptTestSuite struct {
	suite.Suite
	ctx         *processors.Context
	tempDir     string
	assemblyDir string
	includeDir  string
	excludeDir  string
}

func (s *parserIncludeExceptTestSuite) writeFile(contents string, directory string) string {
	filename := uuid.NewString() + ".ra"
	file, err := os.Create(path.Join(directory, filename))
	s.NoError(err, "couldn't create %s file in directory %s", filename, directory)

	_, err = file.WriteString(contents)
	s.NoError(err)

	return filepath.Join(directory, filename)
}

func TestParserRunIncludeExceptTestSuite(t *testing.T) {
	suite.Run(t, new(parserIncludeExceptTestSuite))
}

func (s *parserIncludeExceptTestSuite) SetupTest() {
	var err error
	s.tempDir, err = os.MkdirTemp("", "include-except-tests")
	s.NoError(err)

	s.assemblyDir = path.Join(s.tempDir, "regex-assembly")
	err = os.MkdirAll(s.assemblyDir, fs.ModePerm)
	s.NoError(err)

	s.includeDir = path.Join(s.assemblyDir, "include")
	err = os.MkdirAll(s.includeDir, fs.ModePerm)
	s.NoError(err)

	s.excludeDir = path.Join(s.assemblyDir, "exclude")
	err = os.MkdirAll(s.excludeDir, fs.ModePerm)
	s.NoError(err)

	rootContext := context.New(s.tempDir, "toolchain.yaml")
	s.ctx = processors.NewContext(rootContext)
}

func (s *parserIncludeExceptTestSuite) TearDownTest() {
	s.NoError(os.RemoveAll(s.tempDir))
}

func (s *parserIncludeExceptTestSuite) TestIncludeExcept_MoreExcludesThanIncludes() {
	includePath := s.writeFile(`\s*include1
leave me alone`, s.includeDir)
	excludePath := s.writeFile(`\s*include1
include2
[a-c]include4+
a*b|include3`, s.excludeDir)
	assemblyPath := s.writeFile(fmt.Sprint("##!> include-except ", includePath, " ", excludePath), s.assemblyDir)

	assemblyFile, err := os.Open(assemblyPath)
	s.NoError(err)
	defer assemblyFile.Close()

	parser := NewParser(s.ctx, assemblyFile)
	actual, _ := parser.Parse(false)

	s.Equal(`leave me alone`, actual.String())
}

func (s *parserIncludeExceptTestSuite) TestIncludeExcept_EmptyLinesRemoved() {
	includePath := s.writeFile(`\s*include1
          
include2
leave me alone

`, s.includeDir)
	excludePath := s.writeFile(`include2

`, s.excludeDir)
	assemblyPath := s.writeFile(fmt.Sprint("##!> include-except ", includePath, " ", excludePath), s.assemblyDir)

	assemblyFile, err := os.Open(assemblyPath)
	s.NoError(err)
	defer assemblyFile.Close()

	parser := NewParser(s.ctx, assemblyFile)
	actual, _ := parser.Parse(false)

	s.Equal(`\s*include1
leave me alone`, actual.String())
}

func (s *parserIncludeExceptTestSuite) TestIncludeExcept_OutOfOrder() {
	includePath := s.writeFile(`
\s*include1
include2
a*b|include3
[a-c]include4+`, s.includeDir)
	excludePath := s.writeFile(`
include2
[a-c]include4+
a*b|include3`, s.excludeDir)
	assemblyPath := s.writeFile(fmt.Sprint("##!> include-except ", includePath, " ", excludePath), s.assemblyDir)

	assemblyFile, err := os.Open(assemblyPath)
	s.NoError(err)
	defer assemblyFile.Close()

	parser := NewParser(s.ctx, assemblyFile)
	actual, _ := parser.Parse(false)

	s.Equal(`\s*include1`, actual.String())
}

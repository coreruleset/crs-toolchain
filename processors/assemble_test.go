// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package processors

import (
	"os"
	"testing"

	"github.com/stretchr/testify/suite"
)

type assembleTestSuite struct {
	suite.Suite
	ctx     *Context
	tempDir string
}

type fileFormatTestSuite assembleTestSuite
type specialCommentsTestSuite assembleTestSuite
type specialCasesTestSuite assembleTestSuite
type preprocessorsTestSuite assembleTestSuite

func (suite *assembleTestSuite) SetupSuite() {
	var err error
	suite.tempDir, err = os.MkdirTemp("", "assemble-test")
	suite.NoError(err)
	suite.ctx = NewContextForDir(suite.tempDir)
}

func (suite *assembleTestSuite) TearDownSuite() {
	err := os.RemoveAll(suite.tempDir)
	suite.NoError(err)
}

func (suite *fileFormatTestSuite) SetupSuite() {
	var err error
	suite.tempDir, err = os.MkdirTemp("", "file-format-test")
	suite.NoError(err)
	suite.ctx = NewContextForDir(suite.tempDir)
}

func (suite *fileFormatTestSuite) TearDownSuite() {
	err := os.RemoveAll(suite.tempDir)
	suite.NoError(err)
}

func (suite *specialCommentsTestSuite) SetupSuite() {
	var err error
	suite.tempDir, err = os.MkdirTemp("", "special-comments-test")
	suite.NoError(err)
	suite.ctx = NewContextForDir(suite.tempDir)
}

func (suite *specialCommentsTestSuite) TearDownSuite() {
	err := os.RemoveAll(suite.tempDir)
	suite.NoError(err)
}

func (suite *specialCasesTestSuite) SetupSuite() {
	var err error
	suite.tempDir, err = os.MkdirTemp("", "special-cases-test")
	suite.NoError(err)
	suite.ctx = NewContextForDir(suite.tempDir)
}

func (suite *specialCasesTestSuite) TearDownSuite() {
	err := os.RemoveAll(suite.tempDir)
	suite.NoError(err)
}

func TestRunAssembleTestSuite(t *testing.T) {
	suite.Run(t, new(assembleTestSuite))
	suite.Run(t, new(fileFormatTestSuite))
}

func (s *assembleTestSuite) TestNewAssemble() {
	assemble := NewAssemble(s.ctx)

	s.NotNil(assemble)
	s.Equal(assemble.proc.ctx.rootDirectory, s.tempDir)
	s.Equal(assemble.proc.ctx.dataFilesDirectory, s.tempDir+"/data")
}

func (s *assembleTestSuite) TestAssemble_MultipleLines() {
	assemble := NewAssemble(s.ctx)
	assemble.ProcessLine("homer")
	assemble.ProcessLine("simpson")
	output, err := assemble.Complete()

	s.NoError(err)
	s.Len(output, 1)
	s.Equal("homer|simpson", output[0])
}

func (s *assembleTestSuite) TestAssemble_RegularExpressions() {
	assemble := NewAssemble(s.ctx)
	assemble.ProcessLine("home[r,]")
	assemble.ProcessLine(".imps[a-c]{2}n")
	output, err := assemble.Complete()

	s.NoError(err)
	s.Len(output, 1)
	s.Equal("home[,r]|(?-s:.)imps[a-c]{2}n", output[0])
}

func (s *assembleTestSuite) TestAssemble_InvalidRegularExpressionFails() {
	assemble := NewAssemble(s.ctx)
	assemble.ProcessLine("home[r")
	_, err := assemble.Complete()
	s.Error(err)
}

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

func (suite *assembleTestSuite) SetupSuite() {
	var err error
	suite.tempDir, err = os.MkdirTemp("", "assemble-test")
	suite.NoError(err)
	suite.ctx = NewContext(suite.tempDir)
}

func (suite *assembleTestSuite) TearDownSuite() {
	err := os.RemoveAll(suite.tempDir)
	suite.NoError(err)
}

func (suite *fileFormatTestSuite) SetupSuite() {
	var err error
	suite.tempDir, err = os.MkdirTemp("", "file-format-test")
	suite.NoError(err)
	suite.ctx = NewContext(suite.tempDir)
}

func (suite *fileFormatTestSuite) TearDownSuite() {
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
	s.Equal(assemble.proc.ctx.RootContext().RootDir(), s.tempDir)
	s.Equal(assemble.proc.ctx.RootContext().DataDir(), s.tempDir+"/regex-assembly")
}

func (s *assembleTestSuite) TestAssemble_MultipleLines() {
	assemble := NewAssemble(s.ctx)
	err := assemble.ProcessLine("homer")
	s.NoError(err)
	err = assemble.ProcessLine("simpson")
	s.NoError(err)
	output, err := assemble.Complete()

	s.NoError(err)
	s.Len(output, 1)
	s.Equal("(?:(?:homer|simpson))", output[0])
}

func (s *assembleTestSuite) TestAssemble_RegularExpressions() {
	assemble := NewAssemble(s.ctx)
	err := assemble.ProcessLine("home[r,]")
	s.NoError(err)
	err = assemble.ProcessLine(".imps[a-c]{2}n")
	s.NoError(err)
	output, err := assemble.Complete()

	s.NoError(err)
	s.Len(output, 1)
	s.Equal("(?:(?:home[,r]|(?-s:.)imps[a-c]{2}n))", output[0])
}

func (s *assembleTestSuite) TestAssemble_InvalidRegularExpressionFails() {
	assemble := NewAssemble(s.ctx)
	err := assemble.ProcessLine("home[r")
	s.NoError(err)

	_, err = assemble.Complete()
	s.Error(err)
}

// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package processors

import (
	"path"
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/coreruleset/crs-toolchain/v2/context"
)

type assembleTestSuite struct {
	suite.Suite
	rootDir string
	ctx     *Context
}

type fileFormatTestSuite assembleTestSuite

func (suite *assembleTestSuite) SetupSuite() {
	suite.rootDir = suite.T().TempDir()
	rootContext := context.New(suite.rootDir, "toolchain.yaml")
	suite.ctx = NewContext(rootContext)
}

func (suite *fileFormatTestSuite) SetupSuite() {
	rootContext := context.New(suite.rootDir, "toolchain.yaml")
	suite.ctx = NewContext(rootContext)
}

func TestRunAssembleTestSuite(t *testing.T) {
	suite.Run(t, new(assembleTestSuite))
	suite.Run(t, new(fileFormatTestSuite))
}

func (s *assembleTestSuite) TestNewAssemble() {
	assemble := NewAssemble(s.ctx)

	s.NotNil(assemble)
	s.Equal(assemble.proc.ctx.RootContext().RootDir(), s.rootDir)
	s.Equal(assemble.proc.ctx.RootContext().AssemblyDir(), path.Join(s.rootDir, "/regex-assembly"))
}

func (s *assembleTestSuite) TestAssemble_MultipleLines() {
	assemble := NewAssemble(s.ctx)
	err := assemble.ProcessLine("homer")
	s.Require().NoError(err)
	err = assemble.ProcessLine("simpson")
	s.Require().NoError(err)
	output, err := assemble.Complete()

	s.Require().NoError(err)
	s.Len(output, 1)
	s.Equal("(?:(?:homer|simpson))", output[0])
}

func (s *assembleTestSuite) TestAssemble_RegularExpressions() {
	assemble := NewAssemble(s.ctx)
	err := assemble.ProcessLine("home[r,]")
	s.Require().NoError(err)
	err = assemble.ProcessLine(".imps[a-c]{2}n")
	s.Require().NoError(err)
	output, err := assemble.Complete()

	s.Require().NoError(err)
	s.Len(output, 1)
	s.Equal("(?:(?:(?-s:home[,r]|.imps[a-c]{2}n)))", output[0])
}

func (s *assembleTestSuite) TestAssemble_InvalidRegularExpressionFails() {
	assemble := NewAssemble(s.ctx)
	err := assemble.ProcessLine("home[r")
	s.Require().NoError(err)

	_, err = assemble.Complete()
	s.Error(err)
}

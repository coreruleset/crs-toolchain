// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package processors

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type assembleTestSuite struct {
	suite.Suite
}

var tempDir string

func (suite *assembleTestSuite) SetupSuite() {
	var err error
	tempDir, err = os.MkdirTemp("", "assemble-test")
	suite.NoError(err)
}

func (suite *assembleTestSuite) TearDownSuite() {
	err := os.RemoveAll(tempDir)
	suite.NoError(err)
}

func (suite *assembleTestSuite) TearDownTest() {
	matches, err := filepath.Glob(tempDir + "*")
	if suite.NoError(err) {
		for _, entry := range matches {
			err := os.RemoveAll(entry)
			suite.NoError(err)
		}
	}
}

func TestRunAssembleTestSuite(t *testing.T) {
	suite.Run(t, new(assembleTestSuite))
}

func (s *assembleTestSuite) TestNewAssemble() {
	assemble := NewAssemble(NewContextForDir(tempDir))

	assert.NotNil(s.T(), assemble)
	assert.Equal(s.T(), assemble.proc.ctx.rootDirectory, tempDir)
	assert.Equal(s.T(), assemble.proc.ctx.dataFilesDirectory, tempDir+"/data")
}

func (s *assembleTestSuite) TestAssemble_MultipleLines() {
	assemble := NewAssemble(NewContextForDir(tempDir))
	assemble.ProcessLine("homer")
	assemble.ProcessLine("simpson")
	output, err := assemble.Complete()

	assert.NoError(s.T(), err)
	assert.Len(s.T(), output, 1)
	assert.Equal(s.T(), "homer|simpson", output[0])
}

func (s *assembleTestSuite) TestAssemble_RegularExpressions() {
	assemble := NewAssemble(NewContextForDir(tempDir))
	assemble.ProcessLine("home[r,]")
	assemble.ProcessLine(".imps[a-c]{2}n")
	output, err := assemble.Complete()

	assert.NoError(s.T(), err)
	assert.Len(s.T(), output, 1)
	assert.Equal(s.T(), "home[,r]|(?-s:.)imps[a-c]{2}n", output[0])
}

func (s *assembleTestSuite) TestAssemble_InvalidRegularExpressionFails() {
	assemble := NewAssemble(NewContextForDir(tempDir))
	assemble.ProcessLine("home[r")
	_, err := assemble.Complete()
	assert.Error(s.T(), err)
}

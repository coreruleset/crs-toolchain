// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package regex

import (
	"io/fs"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/coreruleset/crs-toolchain/v2/cmd/internal"
	regexInternal "github.com/coreruleset/crs-toolchain/v2/cmd/regex/internal"
)

type regexTestSuite struct {
	suite.Suite
	rootDir    string
	dataDir    string
	rulesDir   string
	cmdContext *regexInternal.CommandContext
}

func (s *regexTestSuite) SetupTest() {
	s.rootDir = s.T().TempDir()
	s.dataDir = path.Join(s.rootDir, "regex-assembly")
	err := os.MkdirAll(s.dataDir, fs.ModePerm)
	s.Require().NoError(err)

	s.rulesDir = path.Join(s.rootDir, "rules")
	err = os.Mkdir(s.rulesDir, fs.ModePerm)
	s.Require().NoError(err)

	outerContext := internal.NewCommandContext(s.rootDir)
	s.cmdContext = regexInternal.NewCommandContext(outerContext, &logger)
}

func TestRunRegexTestSuite(t *testing.T) {
	suite.Run(t, new(regexTestSuite))
}

func (s *regexTestSuite) TestRegex_ParseRuleId() {
	err := regexInternal.ParseRuleId("123456", s.cmdContext)
	s.Require().NoError(err)
	s.Equal("123456", s.cmdContext.Id)
	s.Equal("123456.ra", s.cmdContext.FileName)
	s.Equal(uint8(0), s.cmdContext.ChainOffset)
	s.False(s.cmdContext.UseStdin)
}

func (s *regexTestSuite) TestRegex_ParseRuleIdAndChainOffset() {
	err := regexInternal.ParseRuleId("123456-chain19", s.cmdContext)
	s.Require().NoError(err)
	s.Equal("123456", s.cmdContext.Id)
	s.Equal("123456-chain19.ra", s.cmdContext.FileName)
	s.Equal(uint8(19), s.cmdContext.ChainOffset)
	s.False(s.cmdContext.UseStdin)
}

func (s *regexTestSuite) TestRegex_ParseRuleIdAndChainOffsetAndFileName() {
	err := regexInternal.ParseRuleId("123456-chain255.ra", s.cmdContext)
	s.Require().NoError(err)
	s.Equal("123456", s.cmdContext.Id)
	s.Equal("123456-chain255.ra", s.cmdContext.FileName)
	s.Equal(uint8(255), s.cmdContext.ChainOffset)
	s.False(s.cmdContext.UseStdin)
}

func (s *regexTestSuite) TestRegex_ParseRuleIdAndFileName() {
	err := regexInternal.ParseRuleId("123456.ra", s.cmdContext)
	s.Require().NoError(err)
	s.Equal("123456", s.cmdContext.Id)
	s.Equal("123456.ra", s.cmdContext.FileName)
	s.Equal(uint8(0), s.cmdContext.ChainOffset)
	s.False(s.cmdContext.UseStdin)
}

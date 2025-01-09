// Copyright 2024 OWASP ModSecurity Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

type utilsTestSuite struct {
	suite.Suite
}

func TestRunUtilsTestSuite(t *testing.T) {
	suite.Run(t, new(utilsTestSuite))
}

func (s *utilsTestSuite) TestIsEscaped() {
	s.True(IsEscaped(`abc\(de`, 4))
	s.True(IsEscaped(`\(abc`, 1))
	s.True(IsEscaped(`abc\(`, 4))
}

func (s *utilsTestSuite) TestIsEscaped_Backslashes() {
	s.True(IsEscaped(`abc\\de`, 4))
	s.True(IsEscaped(`\\abc`, 1))
	s.True(IsEscaped(`abc\\`, 4))
}

func (s *utilsTestSuite) TestIsEscaped_Not() {
	s.False(IsEscaped(`abc\\(de`, 5))
	s.False(IsEscaped(`\\(abc`, 2))
	s.False(IsEscaped(`abc\\(`, 5))
}

func (s *utilsTestSuite) TestIsEscaped_Not_Backslashes() {
	s.False(IsEscaped(`abc\\\de`, 5))
	s.False(IsEscaped(`\\\abc`, 2))
	s.False(IsEscaped(`abc\\\`, 5))
}

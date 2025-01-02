package regex

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

func (s *utilsTestSuite) TestIsEscaped_NoEscapeSequence() {
	s.False(IsEscaped("abc", 0))
	s.False(IsEscaped("abc", 1))
	s.False(IsEscaped("abc", 2))
}

func (s *utilsTestSuite) TestIsEscaped_EscapeSequence() {
	s.False(IsEscaped(`a\bc`, 0))
	s.False(IsEscaped(`a\bc`, 1))
	s.True(IsEscaped(`a\bc`, 2))
	s.False(IsEscaped(`a\bc`, 3))
}

func (s *utilsTestSuite) TestIsEscaped_IgnoreBackslash() {
	s.False(IsEscaped(`a\\\bc`, 0))
	s.False(IsEscaped(`a\\\bc`, 1))
	s.True(IsEscaped(`a\\\bc`, 2))
	s.False(IsEscaped(`a\\\bc`, 3))
	s.True(IsEscaped(`a\\\bc`, 4))
	s.False(IsEscaped(`a\\\bc`, 5))
}

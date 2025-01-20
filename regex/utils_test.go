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

func (s *utilsTestSuite) TestNegativeLookahead() {
	s.Equal(
		"(?i)(?:[^a]|(?:a[^bc])|ab[^c]|ac[^c]|acc[^c])",
		NegativeLookahead([]string{"abc", "accc"}, "(?i)", ""),
	)
	s.Equal(
		"(?i)(?:[^bl]|b[^a]|ba[^d]|bad[^l]|badl[^y]|b[^a]|ba[^d]|l[^y])$",
		NegativeLookahead([]string{"badly", "bad", "ly"}, "(?i)", "$"),
	)
	s.Equal(
		"(?:[^a1]|a[^b]|ab[^c]|1[^2]|12[^3]|123[^4])",
		NegativeLookahead([]string{"abc", "1234"}, "", ""),
	)
}

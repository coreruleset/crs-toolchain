package validation

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/suite"
)

type regexValidationTestSuite struct {
	suite.Suite
}

func TestRunRegexValidationTestSuite(t *testing.T) {
	suite.Run(t, new(regexValidationTestSuite))
}

func (s *regexValidationTestSuite) TestSkipEscapedUnicodeHexEscapePrefix() {
	regex := "\\\\x{invalid}"
	err := ValidateCodePoints(strings.NewReader(regex))
	s.NoError(err)
}

func (s *regexValidationTestSuite) TestSkipEscapedBackSlashBeforeHexEscape() {
	regex := "\\\\\\x{invalid}"
	err := ValidateCodePoints(strings.NewReader(regex))
	s.ErrorContains(err, "strconv.ParseUint: parsing \"invalid\": invalid syntax")
}

func (s *regexValidationTestSuite) TestSkipInvalidUnicodeHexEscape() {
	regex := "\\x{12"
	err := ValidateCodePoints(strings.NewReader(regex))
	s.NoError(err)
}

func (s *regexValidationTestSuite) TestMaxValidCodePoint() {
	regex := "\\x{ff}"
	err := ValidateCodePoints(strings.NewReader(regex))
	s.NoError(err)
}

func (s *regexValidationTestSuite) TestMinInvalidCodePoint() {
	regex := "\\x{100}"
	err := ValidateCodePoints(strings.NewReader(regex))
	s.ErrorContains(err, "Unicode hex escape codepoint too big: 256 > 255")
}

func (s *regexValidationTestSuite) TestMaxInvalidCodePoint() {
	regex := "\\x{10FFFF}"
	err := ValidateCodePoints(strings.NewReader(regex))
	s.ErrorContains(err, "Unicode hex escape codepoint too big: 1114111 > 255")
}

func (s *regexValidationTestSuite) TestFindMultiByteCharacterInCharacterClass() {
	regex := "[🐉]"
	err := ValidateCharacterClasses(strings.NewReader(regex))
	s.ErrorContains(err, "Found multi-byte character in character class: 🐉")
}

func (s *regexValidationTestSuite) TestDontMatchSimpleByteSequences() {
	regex := "[\\x12\\x34]"
	err := ValidateCharacterClasses(strings.NewReader(regex))
	s.NoError(err)
}

func (s *regexValidationTestSuite) TestSkipEscapedCharacterClass() {
	regex := "\\[🐉]"
	err := ValidateCharacterClasses(strings.NewReader(regex))
	s.NoError(err)
}

func (s *regexValidationTestSuite) TestSkipEscapedBackSlash() {
	regex := "\\\\[🐉]"
	err := ValidateCharacterClasses(strings.NewReader(regex))
	s.ErrorContains(err, "Found multi-byte character in character class: 🐉")
}

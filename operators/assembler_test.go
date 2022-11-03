// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"os"
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/theseion/crs-toolchain/v2/processors"
)

type assemblerTestSuite struct {
	suite.Suite
	ctx     *processors.Context
	tempDir string
}

type fileFormatTestSuite assemblerTestSuite
type specialCommentsTestSuite assemblerTestSuite
type specialCasesTestSuite assemblerTestSuite
type preprocessorsTestSuite assemblerTestSuite
type templatesTestSuite assemblerTestSuite

func TestRunAssembleTestSuite(t *testing.T) {
	suite.Run(t, new(fileFormatTestSuite))
	suite.Run(t, new(specialCommentsTestSuite))
	suite.Run(t, new(specialCasesTestSuite))
	suite.Run(t, new(preprocessorsTestSuite))
	suite.Run(t, new(templatesTestSuite))
}

func (s *assemblerTestSuite) SetupSuite() {
	var err error
	s.tempDir, err = os.MkdirTemp("", "assemble-test")
	s.NoError(err)
	s.ctx = processors.NewContext(s.tempDir)
}

func (s *assemblerTestSuite) TearDownSuite() {
	err := os.RemoveAll(s.tempDir)
	s.NoError(err)
}

func (s *fileFormatTestSuite) SetupSuite() {
	var err error
	s.tempDir, err = os.MkdirTemp("", "file-format-test")
	s.NoError(err)
	s.ctx = processors.NewContext(s.tempDir)
}

func (s *fileFormatTestSuite) TearDownSuite() {
	err := os.RemoveAll(s.tempDir)
	s.NoError(err)
}

func (s *specialCommentsTestSuite) SetupSuite() {
	var err error
	s.tempDir, err = os.MkdirTemp("", "special-comments-test")
	s.NoError(err)
	s.ctx = processors.NewContext(s.tempDir)
}

func (s *specialCommentsTestSuite) TearDownSuite() {
	err := os.RemoveAll(s.tempDir)
	s.NoError(err)
}

func (s *specialCasesTestSuite) SetupSuite() {
	var err error
	s.tempDir, err = os.MkdirTemp("", "special-cases-test")
	s.NoError(err)
	s.ctx = processors.NewContext(s.tempDir)
}

func (s *specialCasesTestSuite) TearDownSuite() {
	err := os.RemoveAll(s.tempDir)
	s.NoError(err)
}

func (s *templatesTestSuite) SetupSuite() {
	var err error
	s.tempDir, err = os.MkdirTemp("", "templates-test")
	s.NoError(err)
	s.ctx = processors.NewContext(s.tempDir)
}

func (s *templatesTestSuite) TearDownSuite() {
	err := os.RemoveAll(s.tempDir)
	s.NoError(err)
}

func (s *fileFormatTestSuite) TestPreprocessIgnoresSimpleComments() {
	contents := `##!line1
##! line2
##!\tline3
`
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Run(contents)

	s.NoError(err)
	s.Empty(output)
}

func (s *fileFormatTestSuite) TestPreprocessDoesNotIgnoreSpecialComments() {
	contents := `##!+i
##!+ s
##!^prefix
##!^ prefix
##!$suffix
##!$ suffix
`
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Run(contents)

	s.NoError(err)
	s.Equal("(?is)prefixprefixsuffixsuffix", output)

}

func (s *fileFormatTestSuite) TestPreprocessDoesNotRequireCommentsToStartLine() {
	contents := `##!line1
##! line2
 not blank ##!+is q
\t\t##!foo
\t ##! bar
##!\tline3
`
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Run(contents)

	s.NoError(err)
	s.Len(output, 18)
	s.Equal(` not blank ##!+is `, output)
}

func (s *fileFormatTestSuite) TestPreprocessHandlesPreprocessorComments() {
	contents := `##!> assemble`
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Run(contents)

	s.Error(err)
	s.Empty(output)
}

func (s *fileFormatTestSuite) TestPreprocessIgnoresEmptyLines() {
	contents := `some line

another line`
	assembler := NewAssembler(s.ctx)

	expected := "(?:some|another) line"
	output, err := assembler.Run(contents)

	s.NoError(err)
	s.Equal(expected, output)
}

func (s *fileFormatTestSuite) TestPreprocessFailsOnTooManyEndMarkers() {
	contents := `##!> assemble
##!> assemble
##!<
##!<
##!<
`
	assembler := NewAssembler(s.ctx)

	_, err := assembler.Run(contents)
	s.EqualError(err, "stack is empty", "stack is not empty")
}

func (s *fileFormatTestSuite) TestPreprocessFailsOnTooFewEndMarkers() {
	contents := `##!> assemble
##!> assemble`
	assembler := NewAssembler(s.ctx)

	_, err := assembler.Run(contents)
	s.EqualError(err, "stack has unprocessed items", "stack is empty")
}

func (s *fileFormatTestSuite) TestPreprocessDoesNotRequireFinalEndMarker() {
	contents := `##!> assemble
##!> assemble
##!<
`
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Run(contents)

	s.Error(err)
	s.Empty(output)
}

func (s *specialCommentsTestSuite) TestHandlesIgnoreCaseFlag() {
	for _, contents := range []string{"##!+i\na", "##!+ i\na", "##!+   i\na"} {
		assembler := NewAssembler(s.ctx)
		output, err := assembler.Run(contents)
		s.NoError(err)
		s.Equal("(?i)a", output)
	}
}

func (s *specialCommentsTestSuite) TestHandlesSingleLineFlag() {
	for _, contents := range []string{"##!+s\na", "##!+ s\na", "##!+   s\na"} {
		assembler := NewAssembler(s.ctx)
		output, err := assembler.Run(contents)
		s.NoError(err)
		s.Equal("(?s)a", output)
	}
}

func (s *specialCommentsTestSuite) TestHandlesNoOtherFlags() {
	contents := "##!+mx"
	assembler := NewAssembler(s.ctx)

	s.PanicsWithValue("flag 'm' is not supported", func() { _, _ = assembler.Run(contents) }, "should panic because flags are not supported")
}

func (s *specialCommentsTestSuite) TestHandlesPrefixComment() {
	contents := `##!^ a prefix
a
b`
	assembler := NewAssembler(s.ctx)
	output, err := assembler.Run(contents)
	s.NoError(err)
	s.Equal("a prefix[a-b]", output)
}

func (s *specialCommentsTestSuite) TestHandlesSuffixComment() {
	contents := `##!$ a suffix
a
b`
	assembler := NewAssembler(s.ctx)
	output, err := assembler.Run(contents)
	s.NoError(err)
	s.Equal("[a-b]a suffix", output)
}

func (s *specialCasesTestSuite) TestIgnoresEmptyLines() {
	contents := `some line

another line`
	assembler := NewAssembler(s.ctx)
	output, err := assembler.Run(contents)
	s.NoError(err)
	s.Equal("(?:some|another) line", output)
}

func (s *specialCasesTestSuite) TestReturnsNoOutputForEmptyInput() {
	contents := `##!+ i

`
	assembler := NewAssembler(s.ctx)
	output, err := assembler.Run(contents)
	s.NoError(err)
	s.Empty(output)
}

func (s *specialCasesTestSuite) TestSpecialComments_HandlesBackslashEscapeCorrectly() {
	contents := `\x5c\x5ca`
	assembler := NewAssembler(s.ctx)
	output, err := assembler.Run(contents)
	s.NoError(err)
	s.Equal(`\x5c\x5ca`, output)
}

func (s *specialCasesTestSuite) TestDoesNotDestroyHexEscapes() {
	contents := `a\x5c\x48\\x48b`
	assembler := NewAssembler(s.ctx)
	output, err := assembler.Run(contents)
	s.NoError(err)
	s.Equal(`a\x5cH\x5cx48b`, output)
}

func (s *specialCasesTestSuite) TestDoesNotDestroyHexEscapesInAlternations() {
	contents := `a\x5c\x48
b\x5c\x48
`
	assembler := NewAssembler(s.ctx)
	output, err := assembler.Run(contents)
	s.NoError(err)
	s.Equal(`[a-b]\x5cH`, output)
}

func (s *specialCasesTestSuite) TestSpecialComments_HandlesEscapedAlternationsCorrectly() {
	contents := `\|\|something|or other`
	assembler := NewAssembler(s.ctx)
	output, err := assembler.Run(contents)
	s.NoError(err)
	s.Equal(`\|\|something|or other`, output)
}

func (s *specialCasesTestSuite) TestAlwaysEscapesDoubleQuotes() {
	contents := `(?:"\"\\"a)`
	assembler := NewAssembler(s.ctx)
	output, err := assembler.Run(contents)
	s.NoError(err)
	s.Equal(`\"\"\x5c"a`, output)
}

func (s *specialCasesTestSuite) TestDoesNotConvertHexEscapesOfNonPrintableCharacters() {
	contents := `(?:\x48\xe2\x93\xab)`
	assembler := NewAssembler(s.ctx)
	output, err := assembler.Run(contents)
	s.NoError(err)
	s.Equal(`H\xe2\x93\xab`, output)
}

func (s *specialCasesTestSuite) TestBackslashSReplacesPerlEquivalentCharacterClass() {
	// rassemble-go returns `[\t-\n\f-\r ]` for `\s`, which is correct for Perl
	// but does not include `\v`, which `\s` does in PCRE (3 and 2).
	contents := `\s`
	assembler := NewAssembler(s.ctx)
	output, err := assembler.Run(contents)
	s.NoError(err)
	s.Equal(`[\s\v]`, output)
}

func (s *preprocessorsTestSuite) TestSequentialPreprocessors() {
	contents := `##!> cmdline unix
foo
##!<
##!> cmdline windows
bar
##!<
##!> assemble
one
two
three
##!<
four
five
`
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Run(contents)
	s.NoError(err)
	s.Equal(`f(?:[\"'\[-\x5c]*(?:\$[!#\*\-0-9\?-@_a-\{]*)?\x5c?o[\"'\[-\x5c]*(?:\$[!#\*\-0-9\?-@_a-\{]*)?\x5c?o|our|ive)|b[\"\^]*a[\"\^]*r|one|t(?:wo|hree)`, output)
}

func (s *preprocessorsTestSuite) TestNestedPreprocessors() {
	contents := `##!> assemble
    ##!> cmdline unix
foo
    ##!<
    ##!> cmdline windows
bar
    ##!<
##!<
four
five
`
	assembler := NewAssembler(s.ctx)
	output, err := assembler.Run(contents)
	s.NoError(err)
	s.Equal(`f(?:[\"'\[-\x5c]*(?:\$[!#\*\-0-9\?-@_a-\{]*)?\x5c?o[\"'\[-\x5c]*(?:\$[!#\*\-0-9\?-@_a-\{]*)?\x5c?o|our|ive)|b[\"\^]*a[\"\^]*r`, output)
}

func (s *preprocessorsTestSuite) TestComplexNestedPreprocessors() {
	contents := `##!> assemble
    ##!> cmdline unix
foo
    ##!<
  ##!=>
    ##!> assemble
ab
cd
    ##!<
    ##!> cmdline windows
bar
    ##!<
##!<
four
five
##!> assemble
six
seven
##!<
eight
`
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Run(contents)
	s.NoError(err)
	s.Equal(`f(?:[\"'\[-\x5c]*(?:\$[!#\*\-0-9\?-@_a-\{]*)?\x5c?o[\"'\[-\x5c]*(?:\$[!#\*\-0-9\?-@_a-\{]*)?\x5c?o(?:ab|cd|b[\"\^]*a[\"\^]*r)|our|ive)|s(?:ix|even)|eight`, output)
}

func (s *templatesTestSuite) TestTemplate_ReplacesTemplate() {
	contents := `##!> template id __replaced__
{{id}}
`
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Run(contents)
	s.NoError(err)

	s.Equal("__replaced__", output)
}

func (s *templatesTestSuite) TesTemplate_ReplacesMultipleTemplates() {
	contents := `##!> template id __replaced__
some
{{id}}
other
{{id}}
##! lines
`
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Run(contents)
	s.NoError(err)

	s.Equal("some|__replaced__|other", output)
}

func (s *templatesTestSuite) TestTemplate_IgnoresComments() {
	contents := `##!> template id __replaced__
##! {{id}}
`
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Run(contents)
	s.NoError(err)

	s.Equal("", output)
}

func (s *templatesTestSuite) TestTemplate_ReplacesMultiplePerLine() {
	contents := `##!> template id __replaced__
{{id}}some{{id}}other{{id}}
##! lines
`
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Run(contents)
	s.NoError(err)

	s.Equal("__replaced__some__replaced__other__replaced__", output)
}

func (s *templatesTestSuite) TestTemplate_RetainsEscapes() {
	contents := `##!> template id \n\s\b\v\t
{{id}}
`
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Run(contents)
	s.NoError(err)

	s.Equal(`\n[\s\v]\b\v\t`, output)

}

func (s *templatesTestSuite) TestTemplate_ReplacseOnlySpecifiedTemplate() {
	contents := `##!> template slashes [/\\]
regex with {{slashes}} and {{dots}}
`
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Run(contents)
	s.NoError(err)

	s.Equal(`regex with [/\x5c] and \{\{dots\}\}`, output)
}

func (s *templatesTestSuite) TestTemplate_ReplacesAllNormalOrder() {
	contents := `##!> template slashes [/\\]
##!> template dots [.,;]
regex with {{slashes}} and {{dots}}
`
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Run(contents)
	s.NoError(err)

	s.Equal(`regex with [/\x5c] and [,\.;]`, output)
}

func (s *templatesTestSuite) TestTemplate_ReplacesAllInverseOrder() {
	contents := `##!> template slashes [/\\]
##!> template dots [.,;]
regex with {{dots}} and {{slashes}}
`
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Run(contents)
	s.NoError(err)

	s.Equal(`regex with [,\.;] and [/\x5c]`, output)
}

func (s *templatesTestSuite) TestTemplate_ReplacseOnAllLines() {
	contents := `##!> template slashes [/\\]
##!> template dots [.,;]
##!> template other {{slashes}}+
{{slashes}}
##!=>
{{dots}}
##!=>
regex with {{slashes}} and {{dots}}
##!=>
{{other}}
##!=>
`
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Run(contents)
	s.NoError(err)

	s.Equal(`[/\x5c][,\.;]regex with [/\x5c] and [,\.;][/\x5c]+`, output)
}

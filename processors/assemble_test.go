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
	tempDir string
}

type fileFormatTestSuite assembleTestSuite
type specialCommentsTestSuite assembleTestSuite
type specialCasesTestSuite assembleTestSuite

func (suite *assembleTestSuite) SetupSuite() {
	var err error
	suite.tempDir, err = os.MkdirTemp("", "assemble-test")
	suite.NoError(err)
}

func (suite *assembleTestSuite) TearDownSuite() {
	err := os.RemoveAll(suite.tempDir)
	suite.NoError(err)
}

func (suite *fileFormatTestSuite) SetupSuite() {
	var err error
	suite.tempDir, err = os.MkdirTemp("", "file-format-test")
	suite.NoError(err)
}

func (suite *fileFormatTestSuite) TearDownSuite() {
	err := os.RemoveAll(suite.tempDir)
	suite.NoError(err)
}

func (suite *specialCommentsTestSuite) SetupSuite() {
	var err error
	suite.tempDir, err = os.MkdirTemp("", "special-comments-test")
	suite.NoError(err)
}

func (suite *specialCommentsTestSuite) TearDownSuite() {
	err := os.RemoveAll(suite.tempDir)
	suite.NoError(err)
}

func (suite *specialCasesTestSuite) SetupSuite() {
	var err error
	suite.tempDir, err = os.MkdirTemp("", "special-cases-test")
	suite.NoError(err)
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
	assemble := NewAssemble(NewContextForDir(s.tempDir))

	s.NotNil(assemble)
	s.Equal(assemble.proc.ctx.rootDirectory, s.tempDir)
	s.Equal(assemble.proc.ctx.dataFilesDirectory, s.tempDir+"/data")
}

func (s *assembleTestSuite) TestAssemble_MultipleLines() {
	assemble := NewAssemble(NewContextForDir(s.tempDir))
	assemble.ProcessLine("homer")
	assemble.ProcessLine("simpson")
	output, err := assemble.Complete()

	s.NoError(err)
	s.Len(output, 1)
	s.Equal("homer|simpson", output[0])
}

func (s *assembleTestSuite) TestAssemble_RegularExpressions() {
	assemble := NewAssemble(NewContextForDir(s.tempDir))
	assemble.ProcessLine("home[r,]")
	assemble.ProcessLine(".imps[a-c]{2}n")
	output, err := assemble.Complete()

	s.NoError(err)
	s.Len(output, 1)
	s.Equal("home[,r]|(?-s:.)imps[a-c]{2}n", output[0])
}

func (s *assembleTestSuite) TestAssemble_InvalidRegularExpressionFails() {
	assemble := NewAssemble(NewContextForDir(s.tempDir))
	assemble.ProcessLine("home[r")
	_, err := assemble.Complete()
	s.Error(err)
}

func (s *fileFormatTestSuite) TestPreprocessIgnoresSimpleComments() {
	contents := `##!line1
##! line2
##!\tline3
`
	assembler := NewAssembler(context)

	output, err := assembler.Preprocess(Peekerator(contents.splitlines()))

	s.Empty(output)
}

func (s *fileFormatTestSuite) TestPreprocessDoesNotIgnoreSpecialComments() {
	contents := `##!+i
##!+ smx
##!^prefix
##!^ prefix
##!$suffix
##!$ suffix
`
	assembler := NewAssembler(context)

	output, err := assembler.preprocess(Peekerator(contents.splitlines()))

	s.Equal(contents.splitlines(), output)

}

func (s *fileFormatTestSuite) TestPreprocessDoesNotRequireCommentsToStartLine() {
	contents := `##!line1
 ##! line2
 not blank ##!+smx 
\t\t##!foo
\t ##! bar
##!\tline3
`
	assembler := NewAssembler(context)

	output, err := assembler.preprocess(Peekerator(contents.splitlines()))

	s.Len(output, 1)
	s.Equal(` not blank ##!+smx `, output[0])
}

func (s *fileFormatTestSuite) TestPreprocessHandlesPreprocessorComments() {
	contents := `##!> assemble`
	assembler := NewAssembler(context)

	output, err := assembler.preprocess(Peekerator(contents.splitlines()))

	s.Empty(output)
}

func (s *fileFormatTestSuite) TestPreprocessIgnoresEmptyLines() {
	contents := `some line

another line`
	assembler := NewAssembler(context)

	output, err := assembler.preprocess(Peekerator(contents.splitlines()))

	s.Equal([]string{
		"some line",
		"another line",
	}, output)
}

func (s *fileFormatTestSuite) TestPreprocessFailsOnTooManyEndMarkers() {
	contents := `##!> assemble
##!> assemble
##!<
##!<
##!<
`
	assembler := NewAssembler(context)

	err := assembler.preprocess(Peekerator(contents.splitlines()))
	s.ErrorIs(err, NestingError)
}

func (s *fileFormatTestSuite) TestPreprocessFailsOnTooFewEndMarkers() {
	contents := `##!> assemble
##!> assemble`
	assembler := NewAssembler(context)

	err := assembler.preprocess(Peekerator(contents.splitlines()))
	s.ErrorIs(err, NestingError)
}

func (s *fileFormatTestSuite) TestPreprocessDoesNotRequireFinalEndMarker() {
	contents := `##!> assemble
##!> assemble
##!<
`
	assembler := NewAssembler(context)

	output, err := assembler.preprocess(Peekerator(contents.splitlines()))

	s.Empty(output)
}

func (s *specialCommentsTestSuite) TestHandlesIgnoreCaseFlag() {
	for _, contents := range []string{"##!+i", "##!+ i", "##!+   i"} {
		assembler := NewAssembler(context)
		output, err := assembler.Run(Peekerator(contents.splitlines()))

		s.Equal("(?i)", output)
	}
}

func (s *specialCommentsTestSuite) TestHandlesSingleLineFlag() {
	for contents := range []string{"##!+s", "##!+ s", "##!+   s"} {
		assembler := NewAssembler(context)
		output, err := assembler.Run(Peekerator(contents.splitlines()))

		s.Equal("(?s)", output)
	}
}

func (s *specialCommentsTestSuite) TestHandlesNoOtherFlags() {
	contents := "##!+mx"
	assembler := NewAssembler(context)
	output, err := assembler.Run(Peekerator(contents.splitlines()))

	s.Empty(output)
}

func (s *specialCommentsTestSuite) TestHandlesPrefixComment() {
	contents := `##!^ a prefix
a
b`
	assembler := NewAssembler(context)
	output, err := assembler.Run(Peekerator(contents.splitlines()))

	s.Equal("a prefix[a-b]", output)
}

func (s *specialCommentsTestSuite) TestHandlesSuffixComment() {
	contents := `##!$ a suffix
a
b`
	assembler := NewAssembler(context)
	output, err := assembler.Run(Peekerator(contents.splitlines()))

	s.Equal("[a-b]a suffix", output)
}

func (s *specialCasesTestSuite) TestIgnoresEmptyLines() {
	contents := `some line

another line`
	assembler := NewAssembler(context)
	output, err := assembler.Run(Peekerator(contents.splitlines()))

	s.Equal("(?:some|another) line", output)
}

func (s *specialCasesTestSuite) TestReturnsNoOutputForEmptyInput() {
	contents := `##!+ _

`
	assembler := NewAssembler(context)
	output, err := assembler.Run(Peekerator(contents.splitlines()))

	s.Empty(output)
}

func (s *specialCasesTestSuite) TestSpecialComments_HandlesBackslashEscapeCorrectly() {
	contents := `\x5c\x5ca`
	assembler := NewAssembler(context)
	output, err := assembler.Run(Peekerator(contents.splitlines()))

	s.Equal(`\x5c\x5ca`, output)
}

func (s *specialCasesTestSuite) TestDoesNotDestroyHexEscapes() {
	contents := `a\x5c\x48\\x48b`
	assembler := NewAssembler(context)
	output, err := assembler.Run(Peekerator(contents.splitlines()))

	s.Equal(`a\x5cH\x5cx48b`, output)
}

func (s *specialCasesTestSuite) TestDoesNotDestroyHexEscapesInAlternations() {
	contents := `a\x5c\x48
b\x5c\x48
`
	assembler := NewAssembler(context)
	output, err := assembler.Run(Peekerator(contents.splitlines()))

	s.Equal(`[a-b]\x5cH`, output)
}

func (s *specialCasesTestSuite) TestSpecialComments_HandlesEscapedAlternationsCorrectly() {
	contents := `\|\|something|or other`
	assembler := NewAssembler(context)
	output, err := assembler.Run(Peekerator(contents.splitlines()))

	s.Equal(`\|\|something|or other`, output)
}

func (s *specialCasesTestSuite) TestAlwaysEscapesDoubleQuotes() {
	contents := `(?:"\"\\"a)`
	assembler := NewAssembler(context)
	output, err := assembler.Run(Peekerator(contents.splitlines()))

	s.Equal(`\"\"\x5c"a`, output)
}

func (s *specialCasesTestSuite) TestDoesNotConvertHexEscapesOfNonPrintableCharacters() {
	contents := `(?:\x48\xe2\x93\xab)`
	assembler := NewAssembler(context)
	output, err := assembler.Run(Peekerator(contents.splitlines()))

	s.Equal(`H\xe2\x93\xab`, output)
}

func (s *specialCasesTestSuite) TestBackslashSReplacesPerlEquivalentCharacterClass() {
	// rassemble-go returns `[\t-\n\f-\r ]` for `\s`, which is correct for Perl
	// but does not include `\v`, which `\s` does in PCRE (3 and 2).
	contents := `\s`
	assembler := NewAssembler(context)
	output, err := assembler.Run(Peekerator(contents.splitlines()))

	s.Equal(`\s`, output)
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
	assembler := NewAssembler(context)

	output, err := assembler.preprocess(Peekerator(contents.splitlines()))

	s.Equal([]string{
		`f[\\x5c\"\\"]*o[\\x5c\"\\"]*o`,
		`b[\\"\\^]*a[\\"\\^]*r`,
		`(?:one|t(?:wo|hree))`,
		`four`,
		`five`,
	}, output)
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
	assembler := NewAssembler(context)

	output, err := assembler.preprocess(Peekerator(contents.splitlines()))

	s.Equal([]string{
		`(?:f[""\\]*o[""\\]*o|b["\^]*a["\^]*r)`,
		"four",
		"five",
	}, output)
}

func (s *preprocessorsTestSuite) TestComplexNestedPreprocessors() {
	contents := `##!> assemble, output)
    ##!> cmdline unix
foo
        ##!> assemble
ab
cd
        ##!<
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
	assembler := NewAssembler(context)

	output, err := assembler.preprocess(Peekerator(contents.splitlines()))

	s.Equal([]string{
		`(?:f[""\\]*o[""\\]*o|((?:[""\\]*?[""\\]*:[""\\]*a[""\\]*b|[""\\]*c[""\\]*d)[""\\]*)|b["\^]*a["\^]*r)`,
		"four",
		"five",
		"(?:s(?:ix|even))",
		"eight",
	}, output)
}

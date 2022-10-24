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

func (s *assembleTestSuite) TestFileFormat_PreprocessIgnoresSimpleComments() {
	contents := `##!line1
##! line2
##!\tline3
`
	assembler := NewAssembler(context)

	output, err := assembler.Preprocess(Peekerator(contents.splitlines()))

	assert.Empty(s.T(), output)
}

func (s *assembleTestSuite) TestFileFormat_Preprocess_DoesNotIgnoreSpecialComments() {
	contents := `##!+i
##!+ smx
##!^prefix
##!^ prefix
##!$suffix
##!$ suffix
`
	assembler := NewAssembler(context)

	output, err := assembler.preprocess(Peekerator(contents.splitlines()))

	assert.Equal(s.T(), contents.splitlines(), output)

}

func (s *assembleTestSuite) TestFileFormat_PreprocessDoesNotRequireCommentsToStartLine() {
	contents := `##!line1
 ##! line2
 not blank ##!+smx 
\t\t##!foo
\t ##! bar
##!\tline3
`
	assembler := NewAssembler(context)

	output, err := assembler.preprocess(Peekerator(contents.splitlines()))

	assert.Len(s.T(), output, 1)
	assert.Equal(s.T(), ` not blank ##!+smx `, output[0])
}

func (s *assembleTestSuite) TestFileFormat_PreprocessHandlesPreprocessorComments() {
	contents := `##!> assemble`
	assembler := NewAssembler(context)

	output, err := assembler.preprocess(Peekerator(contents.splitlines()))

	assert.Empty(s.T(), output)
}

func (s *assembleTestSuite) TestFileFormat_PreprocessIgnoresEmptyLines() {
	contents := `some line

another line`
	assembler := NewAssembler(context)

	output, err := assembler.preprocess(Peekerator(contents.splitlines()))

	assert.Equal(s.T(), []string{
		"some line",
		"another line",
	}, output)
}

func (s *assembleTestSuite) TestFileFormat_PreprocessFailsOnTooManyEndMarkers() {
	contents := `##!> assemble
##!> assemble
##!<
##!<
##!<
`
	assembler := NewAssembler(context)

	err := assembler.preprocess(Peekerator(contents.splitlines()))
	assert.ErrorIs(s.T(), err, NestingError)
}

func (s *assembleTestSuite) TestFileFormat_PreprocessFailsOnTooFewEndMarkers() {
	contents := `##!> assemble
##!> assemble`
	assembler := NewAssembler(context)

	err := assembler.preprocess(Peekerator(contents.splitlines()))
	assert.ErrorIs(s.T(), err, NestingError)
}

func (s *assembleTestSuite) TestFileFormat_PreprocessDoesNotRequireFinalEndMarker() {
	contents := `##!> assemble
##!> assemble
##!<
`
	assembler := NewAssembler(context)

	output, err := assembler.preprocess(Peekerator(contents.splitlines()))

	assert.Empty(s.T(), output)
}

func (s *assembleTestSuite) TestSpecialComments_HandlesIgnoreCaseFlag() {
	for _, contents := range []string{"##!+i", "##!+ i", "##!+   i"} {
		assembler := NewAssembler(context)
		output, err := assembler.Run(Peekerator(contents.splitlines()))

		assert.Equal(s.T(), "(?i)", output)
	}
}

func (s *assembleTestSuite) TestSpecialComments_HandlesSingleLineFlag() {
	for contents := range []string{"##!+s", "##!+ s", "##!+   s"} {
		assembler := NewAssembler(context)
		output, err := assembler.Run(Peekerator(contents.splitlines()))

		assert.Equal(s.T(), "(?s)", output)
	}
}

func (s *assembleTestSuite) TestSpecialComments_HandlesNoOtherFlags() {
	contents := "##!+mx"
	assembler := NewAssembler(context)
	output, err := assembler.Run(Peekerator(contents.splitlines()))

	assert.Empty(s.T(), output)
}

func (s *assembleTestSuite) TestSpecialComments_HandlesPrefixComment() {
	contents := `##!^ a prefix
a
b`
	assembler := NewAssembler(context)
	output, err := assembler.Run(Peekerator(contents.splitlines()))

	assert.Equal(s.T(), "a prefix[a-b]", output)
}

func (s *assembleTestSuite) TestSpecialComments_HandlesSuffixComment() {
	contents := `##!$ a suffix
a
b`
	assembler := NewAssembler(context)
	output, err := assembler.Run(Peekerator(contents.splitlines()))

	assert.Equal(s.T(), "[a-b]a suffix", output)
}

func (s *assembleTestSuite) TestSpecialCases_IgnoresEmptyLines() {
	contents := `some line

another line`
	assembler := NewAssembler(context)
	output, err := assembler.Run(Peekerator(contents.splitlines()))

	assert.Equal(s.T(), "(?:some|another) line", output)
}

func (s *assembleTestSuite) TestSpecialCases_ReturnsNoOutputForEmptyInput() {
	contents := `##!+ _

`
	assembler := NewAssembler(context)
	output, err := assembler.Run(Peekerator(contents.splitlines()))

	assert.Empty(s.T(), output)
}

func (s *assembleTestSuite) TestSpecialCases_SpecialComments_HandlesBackslashEscapeCorrectly() {
	contents := `\x5c\x5ca`
	assembler := NewAssembler(context)
	output, err := assembler.Run(Peekerator(contents.splitlines()))

	assert.Equal(s.T(), `\x5c\x5ca`, output)
}

func (s *assembleTestSuite) TestSpecialCases_DoesNotDestroyHexEscapes() {
	contents := `a\x5c\x48\\x48b`
	assembler := NewAssembler(context)
	output, err := assembler.Run(Peekerator(contents.splitlines()))

	assert.Equal(s.T(), `a\x5cH\x5cx48b`, output)
}

func (s *assembleTestSuite) TestSpecialCases_DoesNotDestroyHexEscapesInAlternations() {
	contents := `a\x5c\x48
b\x5c\x48
`
	assembler := NewAssembler(context)
	output, err := assembler.Run(Peekerator(contents.splitlines()))

	assert.Equal(s.T(), `[a-b]\x5cH`, output)
}

func (s *assembleTestSuite) TestSpecialCases_SpecialComments_HandlesEscapedAlternationsCorrectly() {
	contents := `\|\|something|or other`
	assembler := NewAssembler(context)
	output, err := assembler.Run(Peekerator(contents.splitlines()))

	assert.Equal(s.T(), `\|\|something|or other`, output)
}

func (s *assembleTestSuite) TestSpecialCases_AlwaysEscapesDoubleQuotes() {
	contents := `(?:"\"\\"a)`
	assembler := NewAssembler(context)
	output, err := assembler.Run(Peekerator(contents.splitlines()))

	assert.Equal(s.T(), `\"\"\x5c"a`, output)
}

func (s *assembleTestSuite) TestSpecialCases_DoesNotConvertHexEscapesOfNonPrintableCharacters() {
	contents := `(?:\x48\xe2\x93\xab)`
	assembler := NewAssembler(context)
	output, err := assembler.Run(Peekerator(contents.splitlines()))

	assert.Equal(s.T(), `H\xe2\x93\xab`, output)
}

func (s *assembleTestSuite) TestSpecialCases_BackslashSReplacesPerlEquivalentCharacterClass() {
	// rassemble-go returns `[\t-\n\f-\r ]` for `\s`, which is correct for Perl
	// but does not include `\v`, which `\s` does in PCRE (3 and 2).
	contents := `\s`
	assembler := NewAssembler(context)
	output, err := assembler.Run(Peekerator(contents.splitlines()))

	assert.Equal(s.T(), `\s`, output)
}

func (s *assembleTestSuite) TestPreprocessors_SequentialPreprocessors() {
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

	assert.Equal(s.T(), []string{
		`f[\\x5c\"\\"]*o[\\x5c\"\\"]*o`,
		`b[\\"\\^]*a[\\"\\^]*r`,
		`(?:one|t(?:wo|hree))`,
		`four`,
		`five`,
	}, output)
}

func (s *assembleTestSuite) TestPreprocessors_NestedPreprocessors() {
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

	assert.Equal(s.T(), []string{
		`(?:f[""\\]*o[""\\]*o|b["\^]*a["\^]*r)`,
		"four",
		"five",
	}, output)
}

func (s *assembleTestSuite) TestPreprocessors_ComplexNestedPreprocessors() {
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

	assert.Equal(s.T(), []string{
		`(?:f[""\\]*o[""\\]*o|((?:[""\\]*?[""\\]*:[""\\]*a[""\\]*b|[""\\]*c[""\\]*d)[""\\]*)|b["\^]*a["\^]*r)`,
		"four",
		"five",
		"(?:s(?:ix|even))",
		"eight",
	}, output)
}

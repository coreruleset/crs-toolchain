package operators

import (
	"errors"
	"github.com/stretchr/testify/suite"
	"github.com/theseion/crs-toolchain/v2/processors"
	"os"
	"strings"
	"testing"
)

type assembleTestSuite struct {
	suite.Suite
	ctx     *processors.Context
	tempDir string
}

type fileFormatTestSuite assembleTestSuite
type specialCommentsTestSuite assembleTestSuite
type specialCasesTestSuite assembleTestSuite
type preprocessorsTestSuite assembleTestSuite

func TestRunAssembleTestSuite(t *testing.T) {
	suite.Run(t, new(fileFormatTestSuite))
	suite.Run(t, new(specialCommentsTestSuite))
	suite.Run(t, new(specialCasesTestSuite))
	suite.Run(t, new(preprocessorsTestSuite))
}

func (s *assembleTestSuite) SetupSuite() {
	var err error
	s.tempDir, err = os.MkdirTemp("", "assemble-test")
	s.NoError(err)
	s.ctx = processors.NewContextForDir(s.tempDir)
}

func (s *assembleTestSuite) TearDownSuite() {
	err := os.RemoveAll(s.tempDir)
	s.NoError(err)
}

func (s *fileFormatTestSuite) SetupSuite() {
	var err error
	s.tempDir, err = os.MkdirTemp("", "file-format-test")
	s.NoError(err)
	s.ctx = processors.NewContextForDir(s.tempDir)
}

func (s *fileFormatTestSuite) TearDownSuite() {
	err := os.RemoveAll(s.tempDir)
	s.NoError(err)
}

func (s *specialCommentsTestSuite) SetupSuite() {
	var err error
	s.tempDir, err = os.MkdirTemp("", "special-comments-test")
	s.NoError(err)
	s.ctx = processors.NewContextForDir(s.tempDir)
}

func (s *specialCommentsTestSuite) TearDownSuite() {
	err := os.RemoveAll(s.tempDir)
	s.NoError(err)
}

func (s *specialCasesTestSuite) SetupSuite() {
	var err error
	s.tempDir, err = os.MkdirTemp("", "special-cases-test")
	s.NoError(err)
	s.ctx = processors.NewContextForDir(s.tempDir)
}

func (s *specialCasesTestSuite) TearDownSuite() {
	err := os.RemoveAll(s.tempDir)
	s.NoError(err)
}

func (s *fileFormatTestSuite) TestPreprocessIgnoresSimpleComments() {
	contents := `##!line1
##! line2
##!\tline3
`
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Preprocess(Peekerator(strings.Split(contents, "\n")))

	s.Error(err)
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
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Preprocess(Peekerator(strings.Split(contents, "\n")))

	s.Error(err)
	s.Equal(strings.Split(contents, "\n"), output)

}

func (s *fileFormatTestSuite) TestPreprocessDoesNotRequireCommentsToStartLine() {
	contents := `##!line1
 ##! line2
 not blank ##!+smx 
\t\t##!foo
\t ##! bar
##!\tline3
`
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Preprocess(Peekerator(strings.Split(contents, "\n")))

	s.Error(err)
	s.Len(output, 1)
	s.Equal(` not blank ##!+smx `, output[0])
}

func (s *fileFormatTestSuite) TestPreprocessHandlesPreprocessorComments() {
	contents := `##!> assemble`
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Preprocess(Peekerator(strings.Split(contents, "\n")))

	s.Error(err)
	s.Empty(output)
}

func (s *fileFormatTestSuite) TestPreprocessIgnoresEmptyLines() {
	contents := `some line

another line`
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Preprocess(Peekerator(strings.Split(contents, "\n")))

	s.Error(err)
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
	assembler := NewAssembler(s.ctx)

	_, err := assembler.Preprocess(Peekerator(strings.Split(contents, "\n")))
	s.ErrorIs(err, errors.New("NestingError"))
}

func (s *fileFormatTestSuite) TestPreprocessFailsOnTooFewEndMarkers() {
	contents := `##!> assemble
##!> assemble`
	assembler := NewAssembler(s.ctx)

	_, err := assembler.Preprocess(Peekerator(strings.Split(contents, "\n")))
	s.ErrorIs(err, errors.New("NestingError"))
}

func (s *fileFormatTestSuite) TestPreprocessDoesNotRequireFinalEndMarker() {
	contents := `##!> assemble
##!> assemble
##!<
`
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Preprocess(Peekerator(strings.Split(contents, "\n")))

	s.Error(err)
	s.Empty(output)
}

func (s *specialCommentsTestSuite) TestHandlesIgnoreCaseFlag() {
	for _, contents := range []string{"##!+i", "##!+ i", "##!+   i"} {
		assembler := NewAssembler(s.ctx)
		output, err := assembler.Run(Peekerator(strings.Split(contents, "\n")))
		s.Error(err)
		s.Equal("(?i)", output)
	}
}

func (s *specialCommentsTestSuite) TestHandlesSingleLineFlag() {
	for _, contents := range []string{"##!+s", "##!+ s", "##!+   s"} {
		assembler := NewAssembler(s.ctx)
		output, err := assembler.Run(Peekerator(strings.Split(contents, "\n")))
		s.Error(err)
		s.Equal("(?s)", output)
	}
}

func (s *specialCommentsTestSuite) TestHandlesNoOtherFlags() {
	contents := "##!+mx"
	assembler := NewAssembler(s.ctx)
	output, err := assembler.Run(Peekerator(strings.Split(contents, "\n")))
	s.Error(err)
	s.Empty(output)
}

func (s *specialCommentsTestSuite) TestHandlesPrefixComment() {
	contents := `##!^ a prefix
a
b`
	assembler := NewAssembler(s.ctx)
	output, err := assembler.Run(Peekerator(strings.Split(contents, "\n")))
	s.Error(err)
	s.Equal("a prefix[a-b]", output)
}

func (s *specialCommentsTestSuite) TestHandlesSuffixComment() {
	contents := `##!$ a suffix
a
b`
	assembler := NewAssembler(s.ctx)
	output, err := assembler.Run(Peekerator(strings.Split(contents, "\n")))
	s.Error(err)
	s.Equal("[a-b]a suffix", output)
}

func (s *specialCasesTestSuite) TestIgnoresEmptyLines() {
	contents := `some line

another line`
	assembler := NewAssembler(s.ctx)
	output, err := assembler.Run(Peekerator(strings.Split(contents, "\n")))
	s.Error(err)
	s.Equal("(?:some|another) line", output)
}

func (s *specialCasesTestSuite) TestReturnsNoOutputForEmptyInput() {
	contents := `##!+ _

`
	assembler := NewAssembler(s.ctx)
	output, err := assembler.Run(Peekerator(strings.Split(contents, "\n")))
	s.Error(err)
	s.Empty(output)
}

func (s *specialCasesTestSuite) TestSpecialComments_HandlesBackslashEscapeCorrectly() {
	contents := `\x5c\x5ca`
	assembler := NewAssembler(s.ctx)
	output, err := assembler.Run(Peekerator(strings.Split(contents, "\n")))
	s.Error(err)
	s.Equal(`\x5c\x5ca`, output)
}

func (s *specialCasesTestSuite) TestDoesNotDestroyHexEscapes() {
	contents := `a\x5c\x48\\x48b`
	assembler := NewAssembler(s.ctx)
	output, err := assembler.Run(Peekerator(strings.Split(contents, "\n")))
	s.Error(err)
	s.Equal(`a\x5cH\x5cx48b`, output)
}

func (s *specialCasesTestSuite) TestDoesNotDestroyHexEscapesInAlternations() {
	contents := `a\x5c\x48
b\x5c\x48
`
	assembler := NewAssembler(s.ctx)
	output, err := assembler.Run(Peekerator(strings.Split(contents, "\n")))
	s.Error(err)
	s.Equal(`[a-b]\x5cH`, output)
}

func (s *specialCasesTestSuite) TestSpecialComments_HandlesEscapedAlternationsCorrectly() {
	contents := `\|\|something|or other`
	assembler := NewAssembler(s.ctx)
	output, err := assembler.Run(Peekerator(strings.Split(contents, "\n")))
	s.Error(err)
	s.Equal(`\|\|something|or other`, output)
}

func (s *specialCasesTestSuite) TestAlwaysEscapesDoubleQuotes() {
	contents := `(?:"\"\\"a)`
	assembler := NewAssembler(s.ctx)
	output, err := assembler.Run(Peekerator(strings.Split(contents, "\n")))
	s.Error(err)
	s.Equal(`\"\"\x5c"a`, output)
}

func (s *specialCasesTestSuite) TestDoesNotConvertHexEscapesOfNonPrintableCharacters() {
	contents := `(?:\x48\xe2\x93\xab)`
	assembler := NewAssembler(s.ctx)
	output, err := assembler.Run(Peekerator(strings.Split(contents, "\n")))
	s.Error(err)
	s.Equal(`H\xe2\x93\xab`, output)
}

func (s *specialCasesTestSuite) TestBackslashSReplacesPerlEquivalentCharacterClass() {
	// rassemble-go returns `[\t-\n\f-\r ]` for `\s`, which is correct for Perl
	// but does not include `\v`, which `\s` does in PCRE (3 and 2).
	contents := `\s`
	assembler := NewAssembler(s.ctx)
	output, err := assembler.Run(Peekerator(strings.Split(contents, "\n")))
	s.Error(err)
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
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Preprocess(Peekerator(strings.Split(contents, "\n")))
	s.Error(err)
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
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Preprocess(Peekerator(strings.Split(contents, "\n")))
	s.Error(err)
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
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Preprocess(Peekerator(strings.Split(contents, "\n")))
	s.Error(err)
	s.Equal([]string{
		`(?:f[""\\]*o[""\\]*o|((?:[""\\]*?[""\\]*:[""\\]*a[""\\]*b|[""\\]*c[""\\]*d)[""\\]*)|b["\^]*a["\^]*r)`,
		"four",
		"five",
		"(?:s(?:ix|even))",
		"eight",
	}, output)
}

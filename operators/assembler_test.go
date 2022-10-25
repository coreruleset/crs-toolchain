package operators

import (
	"github.com/stretchr/testify/suite"
	"github.com/theseion/crs-toolchain/v2/processors"
	"strings"
	"testing"
)

type assemblerTestSuite struct {
	suite.Suite
	ctx *processors.Context
}

func TestAssemblerTestSuite(t *testing.T) {
	suite.Run(t, new(assemblerTestSuite))
}

func (s *assemblerTestSuite) SetupTest() {
	s.ctx = processors.NewContext()
}

func (s *assemblerTestSuite) TestFileFormat_PreprocessIgnoresSimpleComments() {
	contents := `##!line1
##! line2
##!\tline3
`
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Preprocess(Peekerator(strings.Split(contents, "\n")))

	s.NoError(err)
	s.Empty(output)
}

func (s *assemblerTestSuite) TestFileFormat_Preprocess_DoesNotIgnoreSpecialComments() {
	contents := `##!+i
##!+ smx
##!^prefix
##!^ prefix
##!$suffix
##!$ suffix
`
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Preprocess(Peekerator(strings.Split(contents, "\n")))

	s.NoError(err)
	s.Equal(strings.Split(contents, "\n"), output)

}

func (s *assemblerTestSuite) TestFileFormat_PreprocessDoesNotRequireCommentsToStartLine() {
	contents := `##!line1
 ##! line2
 not blank ##!+smx 
\t\t##!foo
\t ##! bar
##!\tline3
`
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Preprocess(Peekerator(strings.Split(contents, "\n")))

	s.NoError(err)
	s.Len(output, 1)
	s.Equal(` not blank ##!+smx `, output[0])
}

func (s *assemblerTestSuite) TestFileFormat_PreprocessHandlesPreprocessorComments() {
	contents := `##!> assemble`
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Preprocess(Peekerator(strings.Split(contents, "\n")))

	s.NoError(err)
	s.Empty(output)
}

func (s *assemblerTestSuite) TestFileFormat_PreprocessIgnoresEmptyLines() {
	contents := `some line

another line`
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Preprocess(Peekerator(strings.Split(contents, "\n")))

	s.NoError(err)
	s.Equal([]string{
		"some line",
		"another line",
	}, output)
}

func (s *assemblerTestSuite) TestFileFormat_PreprocessFailsOnTooManyEndMarkers() {
	contents := `##!> assemble
##!> assemble
##!<
##!<
##!<
`
	assembler := NewAssembler(s.ctx)

	_, err := assembler.Preprocess(Peekerator(strings.Split(contents, "\n")))

	s.Error(err)
	//s.ErrorIs(err, NestingError)
}

func (s *assemblerTestSuite) TestFileFormat_PreprocessFailsOnTooFewEndMarkers() {
	contents := `##!> assemble
##!> assemble`
	assembler := NewAssembler(s.ctx)

	_, err := assembler.Preprocess(Peekerator(strings.Split(contents, "\n")))
	s.NoError(err)
	//s.ErrorIs(err, NestingError)
}

func (s *assemblerTestSuite) TestFileFormat_PreprocessDoesNotRequireFinalEndMarker() {
	contents := `##!> assemble
##!> assemble
##!<
`
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Preprocess(Peekerator(strings.Split(contents, "\n")))

	s.NoError(err)
	s.Empty(output)
}

func (s *assemblerTestSuite) TestSpecialComments_HandlesIgnoreCaseFlag() {
	for _, contents := range []string{"##!+i", "##!+ i", "##!+   i"} {
		assembler := NewAssembler(s.ctx)
		output, err := assembler.Run(Peekerator(strings.Split(contents, "\n")))

		s.NoError(err)
		s.Equal("(?i)", output)
	}
}

func (s *assemblerTestSuite) TestSpecialComments_HandlesSingleLineFlag() {
	for contents := range []string{"##!+s", "##!+ s", "##!+   s"} {
		assembler := NewAssembler(s.ctx)
		output, err := assembler.Run(Peekerator(strings.Split(contents, "\n")))

		s.NoError(err)
		s.Equal("(?s)", output)
	}
}

func (s *assemblerTestSuite) TestSpecialComments_HandlesNoOtherFlags() {
	contents := "##!+mx"
	assembler := NewAssembler(s.ctx)
	output, err := assembler.Run(Peekerator(strings.Split(contents, "\n")))

	s.NoError(err)
	s.Empty(output)
}

func (s *assemblerTestSuite) TestSpecialComments_HandlesPrefixComment() {
	contents := `##!^ a prefix
a
b`
	assembler := NewAssembler(s.ctx)
	output, err := assembler.Run(Peekerator(strings.Split(contents, "\n")))

	s.NoError(err)
	s.Equal("a prefix[a-b]", output)
}

func (s *assemblerTestSuite) TestSpecialComments_HandlesSuffixComment() {
	contents := `##!$ a suffix
a
b`
	assembler := NewAssembler(s.ctx)
	output, err := assembler.Run(Peekerator(strings.Split(contents, "\n")))

	s.NoError(err)
	s.Equal("[a-b]a suffix", output)
}

func (s *assemblerTestSuite) TestSpecialCases_IgnoresEmptyLines() {
	contents := `some line

another line`
	assembler := NewAssembler(s.ctx)
	output, err := assembler.Run(Peekerator(strings.Split(contents, "\n")))

	s.NoError(err)
	s.Equal("(?:some|another) line", output)
}

func (s *assemblerTestSuite) TestSpecialCases_ReturnsNoOutputForEmptyInput() {
	contents := `##!+ _

`
	assembler := NewAssembler(s.ctx)
	output, err := assembler.Run(Peekerator(strings.Split(contents, "\n")))

	s.NoError(err)
	s.Empty(output)
}

func (s *assemblerTestSuite) TestSpecialCases_SpecialComments_HandlesBackslashEscapeCorrectly() {
	contents := `\x5c\x5ca`
	assembler := NewAssembler(s.ctx)
	output, err := assembler.Run(Peekerator(strings.Split(contents, "\n")))

	s.NoError(err)
	s.Equal(`\x5c\x5ca`, output)
}

func (s *assemblerTestSuite) TestSpecialCases_DoesNotDestroyHexEscapes() {
	contents := `a\x5c\x48\\x48b`
	assembler := NewAssembler(s.ctx)
	output, err := assembler.Run(Peekerator(strings.Split(contents, "\n")))

	s.NoError(err)
	s.Equal(`a\x5cH\x5cx48b`, output)
}

func (s *assemblerTestSuite) TestSpecialCases_DoesNotDestroyHexEscapesInAlternations() {
	contents := `a\x5c\x48
b\x5c\x48
`
	assembler := NewAssembler(s.ctx)
	output, err := assembler.Run(Peekerator(strings.Split(contents, "\n")))

	s.NoError(err)
	s.Equal(`[a-b]\x5cH`, output)
}

func (s *assemblerTestSuite) TestSpecialCases_SpecialComments_HandlesEscapedAlternationsCorrectly() {
	contents := `\|\|something|or other`
	assembler := NewAssembler(s.ctx)
	output, err := assembler.Run(Peekerator(strings.Split(contents, "\n")))

	s.NoError(err)
	s.Equal(`\|\|something|or other`, output)
}

func (s *assemblerTestSuite) TestSpecialCases_AlwaysEscapesDoubleQuotes() {
	contents := `(?:"\"\\"a)`
	assembler := NewAssembler(s.ctx)
	output, err := assembler.Run(Peekerator(strings.Split(contents, "\n")))

	s.NoError(err)
	s.Equal(`\"\"\x5c"a`, output)
}

func (s *assemblerTestSuite) TestSpecialCases_DoesNotConvertHexEscapesOfNonPrintableCharacters() {
	contents := `(?:\x48\xe2\x93\xab)`
	assembler := NewAssembler(s.ctx)
	output, err := assembler.Run(Peekerator(strings.Split(contents, "\n")))

	s.NoError(err)
	s.Equal(`H\xe2\x93\xab`, output)
}

func (s *assemblerTestSuite) TestSpecialCases_BackslashSReplacesPerlEquivalentCharacterClass() {
	// rassemble-go returns `[\t-\n\f-\r ]` for `\s`, which is correct for Perl
	// but does not include `\v`, which `\s` does in PCRE (3 and 2).
	contents := `\s`
	assembler := NewAssembler(s.ctx)
	output, err := assembler.Run(Peekerator(strings.Split(contents, "\n")))

	s.NoError(err)
	s.Equal(`\s`, output)
}

func (s *assemblerTestSuite) TestPreprocessors_SequentialPreprocessors() {
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

	s.NoError(err)
	s.Equal([]string{
		`f[\\x5c\"\\"]*o[\\x5c\"\\"]*o`,
		`b[\\"\\^]*a[\\"\\^]*r`,
		`(?:one|t(?:wo|hree))`,
		`four`,
		`five`,
	}, output)
}

func (s *assemblerTestSuite) TestPreprocessors_NestedPreprocessors() {
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
	s.NoError(err)
	s.Equal([]string{
		`(?:f[""\\]*o[""\\]*o|b["\^]*a["\^]*r)`,
		"four",
		"five",
	}, output)
}

func (s *assemblerTestSuite) TestPreprocessors_ComplexNestedPreprocessors() {
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
	s.NoError(err)
	s.Equal([]string{
		`(?:f[""\\]*o[""\\]*o|((?:[""\\]*?[""\\]*:[""\\]*a[""\\]*b|[""\\]*c[""\\]*d)[""\\]*)|b["\^]*a["\^]*r)`,
		"four",
		"five",
		"(?:s(?:ix|even))",
		"eight",
	}, output)
}

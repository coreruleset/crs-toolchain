// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package format

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path"
	"testing"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/suite"

	"github.com/coreruleset/crs-toolchain/v2/cmd/internal"
	regexInternal "github.com/coreruleset/crs-toolchain/v2/cmd/regex/internal"
)

type formatTestSuite struct {
	suite.Suite
	rootDir    string
	dataDir    string
	includeDir string
	cmdContext *regexInternal.CommandContext
	cmd        *cobra.Command
}

func (s *formatTestSuite) SetupTest() {
	s.rootDir = s.T().TempDir()
	s.dataDir = path.Join(s.rootDir, "regex-assembly")
	err := os.MkdirAll(s.dataDir, fs.ModePerm)
	s.Require().NoError(err)

	s.includeDir = path.Join(s.dataDir, "include")
	err = os.MkdirAll(s.includeDir, fs.ModePerm)
	s.Require().NoError(err)

	rootContext := internal.NewCommandContext(s.rootDir)
	s.cmdContext = regexInternal.NewCommandContext(rootContext, &logger)
	s.cmd = New(s.cmdContext)
}

func TestRunFormatTestSuite(t *testing.T) {
	suite.Run(t, new(formatTestSuite))
}

func (s *formatTestSuite) TestFormat_NormalRuleId() {
	s.writeDataFile("123456.ra", "")
	s.cmd.SetArgs([]string{"123456"})
	cmd, _ := s.cmd.ExecuteC()

	s.Equal("format", cmd.Name())

	args := cmd.Flags().Args()
	s.Len(args, 1)
	s.Equal("123456", args[0])
}

func (s *formatTestSuite) TestFormat_NormalIncludeName() {
	s.writeIncludeFile("shell-data.ra", "")
	s.cmd.SetArgs([]string{"shell-data"})
	cmd, _ := s.cmd.ExecuteC()

	s.Equal("format", cmd.Name())

	args := cmd.Flags().Args()
	s.Len(args, 1)
	s.Equal("shell-data", args[0])
}

func (s *formatTestSuite) TestFormat_NoArgument() {
	s.cmd.SetArgs([]string{})
	_, err := s.cmd.ExecuteC()

	s.EqualError(err, "expected RULE_ID, INCLUDE_NAME, or flag, found nothing")
}

func (s *formatTestSuite) TestFormat_ArgumentAndAllFlag() {
	s.cmd.SetArgs([]string{"shell-data", "--all"})
	_, err := s.cmd.ExecuteC()

	s.EqualError(err, "expected RULE_ID, INCLUDE_NAME, or flag, found multiple")
}

func (s *formatTestSuite) TestFormat_Dash() {
	s.cmd.SetArgs([]string{"-"})
	_, err := s.cmd.ExecuteC()

	s.EqualError(err, "invalid argument '-'")

}

func (s *formatTestSuite) TestFormat_TrimsTabs() {
	s.writeDataFile("123456.ra", `line1	
	line2`)
	s.cmd.SetArgs([]string{"123456"})
	_, err := s.cmd.ExecuteC()
	s.Require().NoError(err)

	expected := RegexAssemblyStandardHeader + `
line1	
line2
`
	output := s.readDataFile("123456.ra")
	s.Equal(expected, output)
}

func (s *formatTestSuite) TestFormat_TrimsSpaces() {
	s.writeDataFile("123456.ra", `line1    
    line2`)
	s.cmd.SetArgs([]string{"123456"})
	_, err := s.cmd.ExecuteC()
	s.Require().NoError(err)

	expected := RegexAssemblyStandardHeader + `
line1    
line2
`
	output := s.readDataFile("123456.ra")
	s.Equal(expected, output)
}

func (s *formatTestSuite) TestFormat_IndentsAssembleBlock() {
	s.writeDataFile("123456.ra", `##!> assemble
    		line
##!<`)
	s.cmd.SetArgs([]string{"123456"})
	_, err := s.cmd.ExecuteC()
	s.Require().NoError(err)

	expected := RegexAssemblyStandardHeader + `
##!> assemble
  line
##!<
`
	output := s.readDataFile("123456.ra")
	s.Equal(expected, output)
}

func (s *formatTestSuite) TestFormat_IndentsNestedAssembleBlocks() {
	s.writeDataFile("123456.ra", `            ##!> assemble
    		line
	   ##!> assemble
	               ##!=> output
		##!=< input
			##!> assemble
				line2
			##!> assemble
				line4
			##!<
				line3
##!<
		  ##!=>	
		  			##!<
##!<`)
	s.cmd.SetArgs([]string{"123456"})
	_, err := s.cmd.ExecuteC()
	s.Require().NoError(err)

	expected := RegexAssemblyStandardHeader + `
##!> assemble
  line
  ##!> assemble
    ##!=> output
    ##!=< input
    ##!> assemble
      line2
      ##!> assemble
        line4
      ##!<
      line3
    ##!<
    ##!=>	
  ##!<
##!<
`
	output := s.readDataFile("123456.ra")
	s.Equal(expected, output)
}

func (s *formatTestSuite) TestFormat_EndOfFileHasNewLineAfterNoNewLine() {
	s.writeDataFile("123456.ra", `##!> assemble
    		line
##!<`)
	s.cmd.SetArgs([]string{"123456"})
	_, err := s.cmd.ExecuteC()
	s.Require().NoError(err)

	expected := RegexAssemblyStandardHeader + `
##!> assemble
  line
##!<
`
	output := s.readDataFile("123456.ra")
	s.Equal(expected, output)
}

func (s *formatTestSuite) TestFormat_EndOfFileHasNewLineAfterOneNewLine() {
	s.writeDataFile("123456.ra", `##!> assemble
    		line
##!<
`)
	s.cmd.SetArgs([]string{"123456"})
	_, err := s.cmd.ExecuteC()
	s.Require().NoError(err)

	expected := RegexAssemblyStandardHeader + `
##!> assemble
  line
##!<
`
	output := s.readDataFile("123456.ra")
	s.Equal(expected, output)
}

func (s *formatTestSuite) TestFormat_EndOfFileHasNewLineAfterTwoNewLines() {
	s.writeDataFile("123456.ra", `##!> assemble
    		line
##!<

`)
	s.cmd.SetArgs([]string{"123456"})
	_, err := s.cmd.ExecuteC()
	s.Require().NoError(err)

	expected := RegexAssemblyStandardHeader + `
##!> assemble
  line
##!<
`
	output := s.readDataFile("123456.ra")
	s.Equal(expected, output)
}

func (s *formatTestSuite) TestFormat_EndOfFileHasNewLineIfEmpty() {
	s.writeDataFile("123456.ra", "")

	s.cmd.SetArgs([]string{"123456"})
	_, err := s.cmd.ExecuteC()
	s.Require().NoError(err)
	expected := RegexAssemblyStandardHeader + "\n"
	output := s.readDataFile("123456.ra")
	s.Equal(expected, output)
}

func (s *formatTestSuite) TestFormat_DoesNotRemoveEmptyLines() {
	s.writeDataFile("123456.ra", `        
	
##!> assemble
      
  line
	   
##!<`)
	s.cmd.SetArgs([]string{"123456"})
	_, err := s.cmd.ExecuteC()
	s.Require().NoError(err)

	expected := RegexAssemblyStandardHeader + `


##!> assemble

  line

##!<
`
	output := s.readDataFile("123456.ra")
	s.Equal(expected, output)
}

func (s *formatTestSuite) TestFormat_DoesNotRemoveComments() {
	s.writeDataFile("123456.ra", `##! a comment	
##!> assemble
##! a comment	
  line
##! a comment	
##!<`)
	s.cmd.SetArgs([]string{"123456"})
	_, err := s.cmd.ExecuteC()
	s.Require().NoError(err)

	expected := RegexAssemblyStandardHeader + `
##! a comment	
##!> assemble
  ##! a comment	
  line
  ##! a comment	
##!<
`
	output := s.readDataFile("123456.ra")
	s.Equal(expected, output)
}

func (s *formatTestSuite) TestFormat_OnlyIndentsAssembleProcessor() {
	s.writeDataFile("123456.ra", `##!> assemble
##!> include bart
##!> assemble
##!+ i
##!^ prefix
##!$ suffix
##!> define homer simpson 
##!<

##!<`)
	s.cmd.SetArgs([]string{"123456"})
	_, err := s.cmd.ExecuteC()
	s.Require().NoError(err)

	expected := RegexAssemblyStandardHeader + `
##!> assemble
  ##!> include bart
  ##!> assemble
##!+ i
##!^ prefix
##!$ suffix
    ##!> define homer simpson
  ##!<

##!<
`
	output := s.readDataFile("123456.ra")
	s.Equal(expected, output)
}

func (s *formatTestSuite) TestFormat_FormatsProcessors() {
	s.writeDataFile("123456.ra", `##!>assemble
##!> include 	   bart
##!>       	 cmdline  	windows
##!> define 	homer   	simpson 
##!<
##!<`)
	s.cmd.SetArgs([]string{"123456"})
	_, err := s.cmd.ExecuteC()
	s.Require().NoError(err)

	expected := RegexAssemblyStandardHeader + `
##!> assemble
  ##!> include bart
  ##!> cmdline windows
    ##!> define homer simpson
  ##!<
##!<
`
	output := s.readDataFile("123456.ra")
	s.Equal(expected, output)
}

func (s *formatTestSuite) TestFormat_FormatsFlags() {
	s.writeDataFile("123456.ra", `##!+i
  ##!+ i
##!+ i 	
`)
	s.cmd.SetArgs([]string{"123456"})
	_, err := s.cmd.ExecuteC()
	s.Require().NoError(err)

	expected := RegexAssemblyStandardHeader + `
##!+ i
##!+ i
##!+ i
`
	output := s.readDataFile("123456.ra")
	s.Equal(expected, output)
}

func (s *formatTestSuite) TestFormat_FormatsPrefix() {
	s.writeDataFile("123456.ra", `##!^prefix without separating white space
  ##!^ prefix with leading white space
##!^ prefix with trailing white space 	
`)
	s.cmd.SetArgs([]string{"123456"})
	_, err := s.cmd.ExecuteC()
	s.Require().NoError(err)

	expected := RegexAssemblyStandardHeader + `
##!^ prefix without separating white space
##!^ prefix with leading white space
##!^ prefix with trailing white space
`
	output := s.readDataFile("123456.ra")
	s.Equal(expected, output)
}

func (s *formatTestSuite) TestFormat_FormatsSuffix() {
	s.writeDataFile("123456.ra", `##!$suffix without separating white space
  ##!$ suffix with leading white space
##!$ suffix with trailing white space 	
`)
	s.cmd.SetArgs([]string{"123456"})
	_, err := s.cmd.ExecuteC()
	s.Require().NoError(err)

	expected := RegexAssemblyStandardHeader + `
##!$ suffix without separating white space
##!$ suffix with leading white space
##!$ suffix with trailing white space
`
	output := s.readDataFile("123456.ra")
	s.Equal(expected, output)
}

func (s *formatTestSuite) TestFormat_FormatsDefinitions() {
	s.writeDataFile("123456.ra", `##!>define without-separating-white-space homer
  ##!> define with-leading-white-space homer
##!> define with-trailing-white-space homer 	
`)
	s.cmd.SetArgs([]string{"123456"})
	_, err := s.cmd.ExecuteC()
	s.Require().NoError(err)

	expected := RegexAssemblyStandardHeader + `
##!> define without-separating-white-space homer
##!> define with-leading-white-space homer
##!> define with-trailing-white-space homer
`
	output := s.readDataFile("123456.ra")
	s.Equal(expected, output)
}

func (s *formatTestSuite) TestFormat_FormatsIncludes() {
	s.writeDataFile("123456.ra", `##!>include without-separating-white-space
  ##!> include with-leading-white-space
##!> include with-trailing-white-space 	
`)
	s.cmd.SetArgs([]string{"123456"})
	_, err := s.cmd.ExecuteC()
	s.Require().NoError(err)

	expected := RegexAssemblyStandardHeader + `
##!> include without-separating-white-space
##!> include with-leading-white-space
##!> include with-trailing-white-space
`
	output := s.readDataFile("123456.ra")
	s.Equal(expected, output)
}

func (s *formatTestSuite) TestFormat_FormatsIncludes_WithSuffixReplacements() {
	s.writeDataFile("123456.ra", `##!>include homer
##!> include homer -- r s f g
##!> include marge
`)
	s.cmd.SetArgs([]string{"123456"})
	_, err := s.cmd.ExecuteC()
	s.Require().NoError(err)

	expected := RegexAssemblyStandardHeader + `
##!> include homer
##!> include homer -- r s f g
##!> include marge
`
	output := s.readDataFile("123456.ra")
	s.Equal(expected, output)
}

func (s *formatTestSuite) TestFormat_FormatsExcept() {
	s.writeDataFile("123456.ra", `##!>include-except without-separating-white-space homer
  ##!> include-except with-leading-white-space homer
##!> include-except with-trailing-white-space homer	 
`)
	s.cmd.SetArgs([]string{"123456"})
	_, err := s.cmd.ExecuteC()
	s.Require().NoError(err)

	expected := RegexAssemblyStandardHeader + `
##!> include-except without-separating-white-space homer
##!> include-except with-leading-white-space homer
##!> include-except with-trailing-white-space homer
`
	output := s.readDataFile("123456.ra")
	s.Equal(expected, output)
}

func (s *formatTestSuite) TestFormat_FormatsExcept_WithSuffixReplacements() {
	s.writeDataFile("123456.ra", `##!>include-except simpson homer
##!> include-except includefile exclude1 exclude2 -- @ [\s<>] ~ \S
##!> include-except simpson homer
`)
	s.cmd.SetArgs([]string{"123456"})
	_, err := s.cmd.ExecuteC()
	s.Require().NoError(err)

	expected := RegexAssemblyStandardHeader + `
##!> include-except simpson homer
##!> include-except includefile exclude1 exclude2 -- @ [\s<>] ~ \S
##!> include-except simpson homer
`
	output := s.readDataFile("123456.ra")
	s.Equal(expected, output)
}

func (s *formatTestSuite) TestIgnoreCaseFlagWithUppercase() {
	// send logs to buffer
	out := &bytes.Buffer{}
	log := zerolog.New(out)
	logger = log.With().Str("component", "parser-test").Logger()

	s.writeDataFile("123456.ra", RegexAssemblyStandardHeader+`
##!+ i
this is a regex
^[a-z]this is another regex
{1,3}[Bb]lah
`)
	s.cmd.SetArgs([]string{"-c", "123456"})

	_, err := s.cmd.ExecuteC()
	s.EqualError(err, fmt.Sprintf("File not properly formatted: %s", path.Join(s.dataDir, "123456.ra")))
	s.Contains(out.String(), "123456.ra contains uppercase letters in character classes, but ignore-case flag is set. Please check your source files.")
	s.Contains(out.String(), "{1,3}[Bb]lah\\n======^ [HERE]\\n\"}\n")
}

func (s *formatTestSuite) TestIgnoreCaseFlagWithUppercase_FirstCharacter() {
	// send logs to buffer
	out := &bytes.Buffer{}
	log := zerolog.New(out)
	logger = log.With().Str("component", "parser-test").Logger()

	s.writeDataFile("123456.ra", RegexAssemblyStandardHeader+`
##!+ i
[First] letter is uppercase
`)
	s.cmdContext.OuterContext.Output = internal.GitHub
	s.cmd.SetArgs([]string{"-c", "123456"})

	_, err := s.cmd.ExecuteC()
	s.EqualError(err, fmt.Sprintf("File not properly formatted: %s", path.Join(s.dataDir, "123456.ra")))
	s.Contains(out.String(), "123456.ra contains uppercase letters in character classes, but ignore-case flag is set. Please check your source files.")
	s.Contains(out.String(), "[First] letter is uppercase\\n=^ [HERE]\\n\"}\n")
}

func (s *formatTestSuite) TestIgnoreCaseFlagWithUppercase_LastCharacter() {
	// send logs to buffer
	out := &bytes.Buffer{}
	log := zerolog.New(out)
	logger = log.With().Str("component", "parser-test").Logger()

	s.writeDataFile("123456.ra", RegexAssemblyStandardHeader+`
##!+ i
Last letter is upper[casE]
`)
	s.cmdContext.OuterContext.Output = internal.GitHub
	s.cmd.SetArgs([]string{"-c", "123456"})

	_, err := s.cmd.ExecuteC()
	s.EqualError(err, fmt.Sprintf("File not properly formatted: %s", path.Join(s.dataDir, "123456.ra")))
	s.Contains(out.String(), "123456.ra contains uppercase letters in character classes, but ignore-case flag is set. Please check your source files.")
	s.Contains(out.String(), "Last letter is upper[casE]\\n========================^ [HERE]\\n\"}\n")
}

func (s *formatTestSuite) TestIgnoreCaseFlagWithUppercase_PlusDefinitions() {
	// send logs to buffer
	out := &bytes.Buffer{}
	log := zerolog.New(out)
	logger = log.With().Str("component", "parser-test").Logger()

	s.writeDataFile("123456.ra", RegexAssemblyStandardHeader+`
##!> define homer [simpson]
##!+ i
multiple escape sequences \A\B\S should be good.
`)
	s.cmdContext.OuterContext.Output = internal.GitHub
	s.cmd.SetArgs([]string{"-c", "123456"})

	_, err := s.cmd.ExecuteC()
	s.Require().NoError(err)
}

func (s *formatTestSuite) TestIgnoreCaseFlagWithUppercase_PlusDefinitionsWithUppercase() {
	// send logs to buffer
	out := &bytes.Buffer{}
	log := zerolog.New(out)
	logger = log.With().Str("component", "parser-test").Logger()

	s.writeDataFile("123456.ra", RegexAssemblyStandardHeader+`
##!> define homer No_[Bueno]
##!+ i
multiple escape sequences \A\B\S should be good.
`)
	s.cmdContext.OuterContext.Output = internal.GitHub
	s.cmd.SetArgs([]string{"-c", "123456"})

	_, err := s.cmd.ExecuteC()
	s.EqualError(err, fmt.Sprintf("File not properly formatted: %s", path.Join(s.dataDir, "123456.ra")))
	s.Contains(out.String(), "123456.ra contains uppercase letters in character classes, but ignore-case flag is set. Please check your source files.")
	s.Contains(out.String(), "##!> define homer No_[Bueno]\\n======================^ [HERE]")
}

func (s *formatTestSuite) TestIgnoreCaseFlagWithUppercase_ComplexCharacterClass() {
	// send logs to buffer
	out := &bytes.Buffer{}
	log := zerolog.New(out)
	logger = log.With().Str("component", "parser-test").Logger()

	s.writeDataFile("123456.ra", RegexAssemblyStandardHeader+`
##!+ i
I'm complex: [^S$%_+-fG-].
`)
	s.cmdContext.OuterContext.Output = internal.GitHub
	s.cmd.SetArgs([]string{"-c", "123456"})

	_, err := s.cmd.ExecuteC()
	s.EqualError(err, fmt.Sprintf("File not properly formatted: %s", path.Join(s.dataDir, "123456.ra")))
	s.Contains(out.String(), "123456.ra contains uppercase letters in character classes, but ignore-case flag is set. Please check your source files.")
	s.Contains(out.String(), "I'm complex: [^S$%_+-fG-].\\n===============^ [HERE]")
}

func (s *formatTestSuite) TestIgnoreCaseFlagWithUppercase_CharacterClassWithBrackets() {
	// send logs to buffer
	out := &bytes.Buffer{}
	log := zerolog.New(out)
	logger = log.With().Str("component", "parser-test").Logger()

	s.writeDataFile("123456.ra", RegexAssemblyStandardHeader+`
##!+ i
Chara[ct]er class with brackets: [$l\][2R [fl\]iF]
`)
	s.cmdContext.OuterContext.Output = internal.GitHub
	s.cmd.SetArgs([]string{"-c", "123456"})

	_, err := s.cmd.ExecuteC()
	s.EqualError(err, fmt.Sprintf("File not properly formatted: %s", path.Join(s.dataDir, "123456.ra")))
	s.Contains(out.String(), "123456.ra contains uppercase letters in character classes, but ignore-case flag is set. Please check your source files.")
	s.Contains(out.String(), `Chara[ct]er class with brackets: [$l\\][2R [fl\\]iF]\n========================================^ [HERE]`)
}

func (s *formatTestSuite) TestIgnoreCaseFlagWithUppercase_IgnoreShortHands() {
	// send logs to buffer
	out := &bytes.Buffer{}
	log := zerolog.New(out)
	logger = log.With().Str("component", "parser-test").Logger()

	s.writeDataFile("123456.ra", RegexAssemblyStandardHeader+`
##!+ i
[\W\S]
`)
	s.cmdContext.OuterContext.Output = internal.GitHub
	s.cmd.SetArgs([]string{"-c", "123456"})

	_, err := s.cmd.ExecuteC()
	s.Require().NoError(err)
}

func (s *formatTestSuite) writeDataFile(filename string, contents string) {
	err := os.WriteFile(path.Join(s.dataDir, filename), []byte(contents), fs.ModePerm)
	s.Require().NoError(err)
}

func (s *formatTestSuite) readDataFile(filename string) string {
	output, err := os.ReadFile(path.Join(s.dataDir, filename))
	s.Require().NoError(err)
	return string(output)
}

func (s *formatTestSuite) writeIncludeFile(filename string, contents string) {
	err := os.WriteFile(path.Join(s.includeDir, filename), []byte(contents), fs.ModePerm)
	s.Require().NoError(err)
}

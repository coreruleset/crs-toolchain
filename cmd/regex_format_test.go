// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/suite"
)

type formatTestSuite struct {
	suite.Suite
	tempDir    string
	dataDir    string
	includeDir string
}

func (s *formatTestSuite) SetupTest() {
	rebuildFormatCommand()

	tempDir, err := os.MkdirTemp("", "format-tests")
	s.Require().NoError(err)
	s.tempDir = tempDir

	s.dataDir = path.Join(s.tempDir, "regex-assembly")
	err = os.MkdirAll(s.dataDir, fs.ModePerm)
	s.Require().NoError(err)

	s.includeDir = path.Join(s.dataDir, "include")
	err = os.MkdirAll(s.includeDir, fs.ModePerm)
	s.Require().NoError(err)
}

func (s *formatTestSuite) TearDownTest() {
	err := os.RemoveAll(s.tempDir)
	s.Require().NoError(err)
}

func TestRunFormatTestSuite(t *testing.T) {
	suite.Run(t, new(formatTestSuite))
}

func (s *formatTestSuite) TestFormat_NormalRuleId() {
	s.writeDataFile("123456.ra", "")
	rootCmd.SetArgs([]string{"-d", s.tempDir, "regex", "format", "123456"})
	cmd, _ := rootCmd.ExecuteC()

	s.Equal("format", cmd.Name())

	args := cmd.Flags().Args()
	s.Len(args, 1)
	s.Equal("123456", args[0])
}

func (s *formatTestSuite) TestFormat_NormalIncludeName() {
	s.writeIncludeFile("shell-data.ra", "")
	rootCmd.SetArgs([]string{"-d", s.tempDir, "regex", "format", "shell-data"})
	cmd, _ := rootCmd.ExecuteC()

	s.Equal("format", cmd.Name())

	args := cmd.Flags().Args()
	s.Len(args, 1)
	s.Equal("shell-data", args[0])
}

func (s *formatTestSuite) TestFormat_NoArgument() {
	rootCmd.SetArgs([]string{"regex", "format"})
	_, err := rootCmd.ExecuteC()

	s.EqualError(err, "expected RULE_ID, INCLUDE_NAME, or flag, found nothing")
}

func (s *formatTestSuite) TestFormat_ArgumentAndAllFlag() {
	rootCmd.SetArgs([]string{"regex", "format", "shell-data", "--all"})
	_, err := rootCmd.ExecuteC()

	s.EqualError(err, "expected RULE_ID, INCLUDE_NAME, or flag, found multiple")
}

func (s *formatTestSuite) TestFormat_Dash() {
	rootCmd.SetArgs([]string{"-d", s.tempDir, "regex", "format", "-"})
	_, err := rootCmd.ExecuteC()

	s.EqualError(err, "invalid argument '-'")

}

func (s *formatTestSuite) TestFormat_TrimsTabs() {
	s.writeDataFile("123456.ra", `line1	
	line2`)
	rootCmd.SetArgs([]string{"-d", s.tempDir, "regex", "format", "123456"})
	_, err := rootCmd.ExecuteC()
	s.Require().NoError(err)

	expected := regexAssemblyStandardHeader + `
line1	
line2
`
	output := s.readDataFile("123456.ra")
	s.Equal(expected, output)
}

func (s *formatTestSuite) TestFormat_TrimsSpaces() {
	s.writeDataFile("123456.ra", `line1    
    line2`)
	rootCmd.SetArgs([]string{"-d", s.tempDir, "regex", "format", "123456"})
	_, err := rootCmd.ExecuteC()
	s.Require().NoError(err)

	expected := regexAssemblyStandardHeader + `
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
	rootCmd.SetArgs([]string{"-d", s.tempDir, "regex", "format", "123456"})
	_, err := rootCmd.ExecuteC()
	s.Require().NoError(err)

	expected := regexAssemblyStandardHeader + `
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
	rootCmd.SetArgs([]string{"-d", s.tempDir, "regex", "format", "123456"})
	_, err := rootCmd.ExecuteC()
	s.Require().NoError(err)

	expected := regexAssemblyStandardHeader + `
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
	rootCmd.SetArgs([]string{"-d", s.tempDir, "regex", "format", "123456"})
	_, err := rootCmd.ExecuteC()
	s.Require().NoError(err)

	expected := regexAssemblyStandardHeader + `
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
	rootCmd.SetArgs([]string{"-d", s.tempDir, "regex", "format", "123456"})
	_, err := rootCmd.ExecuteC()
	s.Require().NoError(err)

	expected := regexAssemblyStandardHeader + `
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
	rootCmd.SetArgs([]string{"-d", s.tempDir, "regex", "format", "123456"})
	_, err := rootCmd.ExecuteC()
	s.Require().NoError(err)

	expected := regexAssemblyStandardHeader + `
##!> assemble
  line
##!<
`
	output := s.readDataFile("123456.ra")
	s.Equal(expected, output)
}

func (s *formatTestSuite) TestFormat_EndOfFileHasNewLineIfEmpty() {
	s.writeDataFile("123456.ra", "")
	rootCmd.SetArgs([]string{"-d", s.tempDir, "regex", "format", "123456"})
	_, err := rootCmd.ExecuteC()
	s.Require().NoError(err)

	expected := regexAssemblyStandardHeader + "\n"
	output := s.readDataFile("123456.ra")
	s.Equal(expected, output)
}

func (s *formatTestSuite) TestFormat_DoesNotRemoveEmptyLines() {
	s.writeDataFile("123456.ra", `        
	
##!> assemble
      
  line
	   
##!<`)
	rootCmd.SetArgs([]string{"-d", s.tempDir, "regex", "format", "123456"})
	_, err := rootCmd.ExecuteC()
	s.Require().NoError(err)

	expected := regexAssemblyStandardHeader + `


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
	rootCmd.SetArgs([]string{"-d", s.tempDir, "regex", "format", "123456"})
	_, err := rootCmd.ExecuteC()
	s.Require().NoError(err)

	expected := regexAssemblyStandardHeader + `
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
	rootCmd.SetArgs([]string{"-d", s.tempDir, "regex", "format", "123456"})
	_, err := rootCmd.ExecuteC()
	s.Require().NoError(err)

	expected := regexAssemblyStandardHeader + `
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
	rootCmd.SetArgs([]string{"-d", s.tempDir, "regex", "format", "123456"})
	_, err := rootCmd.ExecuteC()
	s.Require().NoError(err)

	expected := regexAssemblyStandardHeader + `
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
	rootCmd.SetArgs([]string{"-d", s.tempDir, "regex", "format", "123456"})
	_, err := rootCmd.ExecuteC()
	s.Require().NoError(err)

	expected := regexAssemblyStandardHeader + `
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
	rootCmd.SetArgs([]string{"-d", s.tempDir, "regex", "format", "123456"})
	_, err := rootCmd.ExecuteC()
	s.Require().NoError(err)

	expected := regexAssemblyStandardHeader + `
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
	rootCmd.SetArgs([]string{"-d", s.tempDir, "regex", "format", "123456"})
	_, err := rootCmd.ExecuteC()
	s.Require().NoError(err)

	expected := regexAssemblyStandardHeader + `
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
	rootCmd.SetArgs([]string{"-d", s.tempDir, "regex", "format", "123456"})
	_, err := rootCmd.ExecuteC()
	s.Require().NoError(err)

	expected := regexAssemblyStandardHeader + `
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
	rootCmd.SetArgs([]string{"-d", s.tempDir, "regex", "format", "123456"})
	_, err := rootCmd.ExecuteC()
	s.Require().NoError(err)

	expected := regexAssemblyStandardHeader + `
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
	rootCmd.SetArgs([]string{"-d", s.tempDir, "regex", "format", "123456"})
	_, err := rootCmd.ExecuteC()
	s.Require().NoError(err)

	expected := regexAssemblyStandardHeader + `
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
	rootCmd.SetArgs([]string{"-d", s.tempDir, "regex", "format", "123456"})
	_, err := rootCmd.ExecuteC()
	s.Require().NoError(err)

	expected := regexAssemblyStandardHeader + `
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
	rootCmd.SetArgs([]string{"-d", s.tempDir, "regex", "format", "123456"})
	_, err := rootCmd.ExecuteC()
	s.Require().NoError(err)

	expected := regexAssemblyStandardHeader + `
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

	s.writeDataFile("123456.ra", regexAssemblyStandardHeader+`
##!+ i
this is a regex
^[a-z]this is another regex
{1,3}[Bb]lah
`)
	rootCmd.SetArgs([]string{"-d", s.tempDir, "regex", "format", "-c", "123456"})

	_, err := rootCmd.ExecuteC()
	s.EqualError(err, fmt.Sprintf("File not properly formatted: %s", path.Join(s.dataDir, "123456.ra")))

	s.Contains(out.String(), "File contains uppercase letters, but ignore-case flag is set. Please check your source files.")
	s.Contains(out.String(), "{1,3}[Bb]lah\\n=====^ [HERE]\\n\"}\n")
}

func (s *formatTestSuite) TestIgnoreCaseFlagWithUppercasePositionIndicator() {
	// send logs to buffer
	out := &bytes.Buffer{}
	log := zerolog.New(out)
	logger = log.With().Str("component", "parser-test").Logger()

	s.writeDataFile("123456.ra", regexAssemblyStandardHeader+`
##!+ i
First letter is uppercase
`)
	rootCmd.SetArgs([]string{"-d", s.tempDir, "regex", "format", "-c", "123456", "-o", "github"})

	_, err := rootCmd.ExecuteC()
	s.EqualError(err, fmt.Sprintf("File not properly formatted: %s", path.Join(s.dataDir, "123456.ra")))

	s.Contains(out.String(), "File contains uppercase letters, but ignore-case flag is set. Please check your source files.")
	s.Contains(out.String(), "First letter is uppercase\\n^ [HERE]\\n\"}\n")
}

func (s *formatTestSuite) TestIgnoreCaseFlagWithUppercaseEscapedUppercase() {
	// send logs to buffer
	out := &bytes.Buffer{}
	log := zerolog.New(out)
	logger = log.With().Str("component", "parser-test").Logger()

	s.writeDataFile("123456.ra", regexAssemblyStandardHeader+`
##!+ i
this regex has a \S letter which should not match
multiple escape sequences \S\S\S
`)
	rootCmd.SetArgs([]string{"-d", s.tempDir, "regex", "format", "-c", "123456", "-o", "github"})

	_, err := rootCmd.ExecuteC()
	s.NoError(err)
}

func (s *formatTestSuite) TestIgnoreCaseFlagWithUppercaseUnevenlyEscapedUppercase() {
	// send logs to buffer
	out := &bytes.Buffer{}
	log := zerolog.New(out)
	logger = log.With().Str("component", "parser-test").Logger()

	s.writeDataFile("123456.ra", regexAssemblyStandardHeader+`
##!+ i
multiple escape sequences \A\B\S should be good.
odd number of escape sequences should be good also \\\A\\\S
even number of escape sequences should be bad \\\\A\\B
`)
	rootCmd.SetArgs([]string{"-d", s.tempDir, "regex", "format", "-c", "123456", "-o", "github"})

	_, err := rootCmd.ExecuteC()
	s.EqualError(err, fmt.Sprintf("File not properly formatted: %s", path.Join(s.dataDir, "123456.ra")))
	s.Contains(out.String(), "File contains uppercase letters, but ignore-case flag is set. Please check your source files.")
	s.Contains(out.String(), "even number of escape sequences should be bad")
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

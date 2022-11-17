// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"io/fs"
	"os"
	"path"
	"testing"

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
	s.NoError(err)
	s.tempDir = tempDir

	s.dataDir = path.Join(s.tempDir, "data")
	err = os.MkdirAll(s.dataDir, fs.ModePerm)
	s.NoError(err)

	s.includeDir = path.Join(s.dataDir, "include")
	err = os.MkdirAll(s.includeDir, fs.ModePerm)
	s.NoError(err)
}

func (s *formatTestSuite) TearDownTest() {
	err := os.RemoveAll(s.tempDir)
	s.NoError(err)
}

func TestRunFormatTestSuite(t *testing.T) {
	suite.Run(t, new(formatTestSuite))
}

func (s *formatTestSuite) TestFormat_NormalRuleId() {
	s.writeDataFile("123456.data", "")
	rootCmd.SetArgs([]string{"-d", s.tempDir, "regex", "format", "123456"})
	cmd, _ := rootCmd.ExecuteC()

	s.Equal("format", cmd.Name())

	args := cmd.Flags().Args()
	s.Len(args, 1)
	s.Equal("123456", args[0])
}

func (s *formatTestSuite) TestFormat_NormalIncludeName() {
	s.writeIncludeFile("shell-data.data", "")
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

func (s *formatTestSuite) TestFormat_ArumentAndAllFlag() {
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
	s.writeDataFile("123456.data", `line1	
	line2`)
	rootCmd.SetArgs([]string{"-d", s.tempDir, "regex", "format", "123456"})
	_, err := rootCmd.ExecuteC()
	s.NoError(err)

	expected := `line1	
line2
`
	output := s.readDataFile("123456.data")
	s.Equal(expected, output)
}

func (s *formatTestSuite) TestFormat_TrimsSpaces() {
	s.writeDataFile("123456.data", `line1    
    line2`)
	rootCmd.SetArgs([]string{"-d", s.tempDir, "regex", "format", "123456"})
	_, err := rootCmd.ExecuteC()
	s.NoError(err)

	expected := `line1    
line2
`
	output := s.readDataFile("123456.data")
	s.Equal(expected, output)
}

func (s *formatTestSuite) TestFormat_IndentsAssembleBlock() {
	s.writeDataFile("123456.data", `##!> assemble
    		line
##!<`)
	rootCmd.SetArgs([]string{"-d", s.tempDir, "regex", "format", "123456"})
	_, err := rootCmd.ExecuteC()
	s.NoError(err)

	expected := `##!> assemble
  line
##!<
`
	output := s.readDataFile("123456.data")
	s.Equal(expected, output)
}

func (s *formatTestSuite) TestFormat_IndentsNestedAssembleBlocks() {
	s.writeDataFile("123456.data", `            ##!> assemble
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
	s.NoError(err)

	expected := `##!> assemble
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
	output := s.readDataFile("123456.data")
	s.Equal(expected, output)
}

func (s *formatTestSuite) TestFormat_EndOfFileHasNewLineAfterNoNewLine() {
	s.writeDataFile("123456.data", `##!> assemble
    		line
##!<`)
	rootCmd.SetArgs([]string{"-d", s.tempDir, "regex", "format", "123456"})
	_, err := rootCmd.ExecuteC()
	s.NoError(err)

	expected := `##!> assemble
  line
##!<
`
	output := s.readDataFile("123456.data")
	s.Equal(expected, output)
}

func (s *formatTestSuite) TestFormat_EndOfFileHasNewLineAfterOneNewLine() {
	s.writeDataFile("123456.data", `##!> assemble
    		line
##!<
`)
	rootCmd.SetArgs([]string{"-d", s.tempDir, "regex", "format", "123456"})
	_, err := rootCmd.ExecuteC()
	s.NoError(err)

	expected := `##!> assemble
  line
##!<
`
	output := s.readDataFile("123456.data")
	s.Equal(expected, output)
}

func (s *formatTestSuite) TestFormat_EndOfFileHasNewLineAfterTwoNewLines() {
	s.writeDataFile("123456.data", `##!> assemble
    		line
##!<

`)
	rootCmd.SetArgs([]string{"-d", s.tempDir, "regex", "format", "123456"})
	_, err := rootCmd.ExecuteC()
	s.NoError(err)

	expected := `##!> assemble
  line
##!<
`
	output := s.readDataFile("123456.data")
	s.Equal(expected, output)
}

func (s *formatTestSuite) TestFormat_EndOfFileHasNewLineIfEmpty() {
	s.writeDataFile("123456.data", "")
	rootCmd.SetArgs([]string{"-d", s.tempDir, "regex", "format", "123456"})
	_, err := rootCmd.ExecuteC()
	s.NoError(err)

	expected := "\n"
	output := s.readDataFile("123456.data")
	s.Equal(expected, output)
}

func (s *formatTestSuite) TestFormat_DoesNotRemoveEmptyLines() {
	s.writeDataFile("123456.data", `        
	
##!> assemble
      
  line
	   
##!<`)
	rootCmd.SetArgs([]string{"-d", s.tempDir, "regex", "format", "123456"})
	_, err := rootCmd.ExecuteC()
	s.NoError(err)

	expected := `

##!> assemble

  line

##!<
`
	output := s.readDataFile("123456.data")
	s.Equal(expected, output)
}

func (s *formatTestSuite) TestFormat_DoesNotRemoveComments() {
	s.writeDataFile("123456.data", `
##! a comment	
##!> assemble
##! a comment	
  line
##! a comment	
##!<`)
	rootCmd.SetArgs([]string{"-d", s.tempDir, "regex", "format", "123456"})
	_, err := rootCmd.ExecuteC()
	s.NoError(err)

	expected := `
##! a comment	
##!> assemble
  ##! a comment	
  line
  ##! a comment	
##!<
`
	output := s.readDataFile("123456.data")
	s.Equal(expected, output)
}

func (s *formatTestSuite) TestFormat_OnlyIndentsAssembleProcessor() {
	s.writeDataFile("123456.data", `##!> assemble
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
	s.NoError(err)

	expected := `##!> assemble
  ##!> include bart
  ##!> assemble
##!+ i
##!^ prefix
##!$ suffix
    ##!> define homer simpson 
  ##!<

##!<
`
	output := s.readDataFile("123456.data")
	s.Equal(expected, output)
}

func (s *formatTestSuite) TestFormat_FormatsProcessors() {
	s.writeDataFile("123456.data", `##!>assemble
##!> include 	   bart
##!>       	 cmdline  	windows
##!> define 	homer   	simpson 
##!<
##!<`)
	rootCmd.SetArgs([]string{"-d", s.tempDir, "regex", "format", "123456"})
	_, err := rootCmd.ExecuteC()
	s.NoError(err)

	expected := `##!> assemble
  ##!> include bart
  ##!> cmdline windows
    ##!> define homer simpson 
  ##!<
##!<
`
	output := s.readDataFile("123456.data")
	s.Equal(expected, output)
}

func (s *formatTestSuite) writeDataFile(filename string, contents string) {
	err := os.WriteFile(path.Join(s.dataDir, filename), []byte(contents), fs.ModePerm)
	s.NoError(err)
}

func (s *formatTestSuite) readDataFile(filename string) string {
	output, err := os.ReadFile(path.Join(s.dataDir, filename))
	s.NoError(err)
	return string(output)
}

func (s *formatTestSuite) writeIncludeFile(filename string, contents string) {
	err := os.WriteFile(path.Join(s.includeDir, filename), []byte(contents), fs.ModePerm)
	s.NoError(err)
}

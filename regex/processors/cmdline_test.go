// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package processors

import (
	"os"
	"regexp"
	"testing"

	"github.com/stretchr/testify/suite"
)

type cmdLineTestSuite struct {
	suite.Suite
	ctx *Context
}

func (s *cmdLineTestSuite) SetupTest() {
	s.ctx = NewContext(os.TempDir())
}

func TestRunCmdLineTestSuite(t *testing.T) {
	suite.Run(t, new(cmdLineTestSuite))
}

func (s *cmdLineTestSuite) TestCmdLine_NewParser() {
	expected := &CmdLine{
		proc: &Processor{
			ctx:   s.ctx,
			lines: []string{},
		},
		input:   regexp.MustCompile(AssembleInput),
		output:  regexp.MustCompile(AssembleOutput),
		cmdType: CmdLineUnix,
		evasionPatterns: map[EvasionPatterns]string{
			evasionPattern:        `[\x5c'\"\[]*(?:\$[a-z0-9_@?!#{*-]*)?(?:\x5c)?`,
			suffixPattern:         `(?:\s|<|>).*`,
			suffixExpandedCommand: `(?:(?:<|>)|(?:[\w\d._-][\x5c'\"\[]*(?:\$[a-z0-9_@?!#{*-]*)?(?:\x5c)?)+(?:\s|<|>)).*`,
		},
	}
	actual := NewCmdLine(s.ctx, CmdLineUnix)

	s.Equal(expected, actual)
}

func (s *cmdLineTestSuite) TestCmdLine_CmdLineTypeFromString() {
	t, err := CmdLineTypeFromString("unix")
	s.NoError(err)
	cmd := NewCmdLine(s.ctx, t)

	err = cmd.ProcessLine(`foo`)
	s.NoError(err)
	s.Equal(`f[\x5c'\"\[]*(?:\$[a-z0-9_@?!#{*-]*)?(?:\x5c)?o[\x5c'\"\[]*(?:\$[a-z0-9_@?!#{*-]*)?(?:\x5c)?o`, cmd.proc.lines[0])

	t, err = CmdLineTypeFromString("windows")
	s.NoError(err)
	cmd = NewCmdLine(s.ctx, t)

	err = cmd.ProcessLine(`foo`)
	s.NoError(err)
	s.Equal(`f[\"\^]*o[\"\^]*o`, cmd.proc.lines[0])
}

func (s *cmdLineTestSuite) TestCmdLine_BadCmdLineTypeFromString() {
	t, err := CmdLineTypeFromString("nonexistent")
	s.EqualError(err, "bad cmdline option", "cmdline was created even when a bad option was passed")
	s.Equal(t, CmdLineUndefined)
}

func (s *cmdLineTestSuite) TestCmdLine_ProcessLineFoo() {
	cmd := NewCmdLine(s.ctx, CmdLineUnix)

	err := cmd.ProcessLine(`foo`)

	s.NoError(err)
	s.Equal(`f[\x5c'\"\[]*(?:\$[a-z0-9_@?!#{*-]*)?(?:\x5c)?o[\x5c'\"\[]*(?:\$[a-z0-9_@?!#{*-]*)?(?:\x5c)?o`, cmd.proc.lines[0])
}

func (s *cmdLineTestSuite) TestCmdLine_ProcessLinePattern() {
	cmd := NewCmdLine(s.ctx, CmdLineUnix)

	err := cmd.ProcessLine(`gcc-10.`)
	s.NoError(err)

	s.Equal(`g[\x5c'\"\[]*(?:\$[a-z0-9_@?!#{*-]*)?(?:\x5c)?c[\x5c'\"\[]*(?:\$[a-z0-9_@?!#{*-]*)?(?:\x5c)?c[\x5c'\"\[]*(?:\$[a-z0-9_@?!#{*-]*)?(?:\x5c)?\-[\x5c'\"\[]*(?:\$[a-z0-9_@?!#{*-]*)?(?:\x5c)?1[\x5c'\"\[]*(?:\$[a-z0-9_@?!#{*-]*)?(?:\x5c)?0[\x5c'\"\[]*(?:\$[a-z0-9_@?!#{*-]*)?(?:\x5c)?\.`, cmd.proc.lines[0])
}

func (s *cmdLineTestSuite) TestCmdLine_ProcessLineFooWindows() {
	cmd := NewCmdLine(s.ctx, CmdLineWindows)

	err := cmd.ProcessLine(`foo`)
	s.NoError(err)

	s.Equal(`f[\"\^]*o[\"\^]*o`, cmd.proc.lines[0])
}

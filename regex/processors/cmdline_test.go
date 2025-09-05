// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package processors

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/coreruleset/crs-toolchain/v2/configuration"
	"github.com/coreruleset/crs-toolchain/v2/context"
)

type cmdLineTestSuite struct {
	suite.Suite
	ctx *Context
}

func (s *cmdLineTestSuite) SetupTest() {
	rootContext := context.NewWithConfiguration(os.TempDir(), s.newTestConfiguration())
	s.ctx = NewContext(rootContext)
}

func (s *cmdLineTestSuite) newTestConfiguration() *configuration.Configuration {
	return &configuration.Configuration{
		Patterns: configuration.Patterns{
			AntiEvasion: configuration.Pattern{
				Unix:    "_av-u_",
				Windows: "_av-w_",
			},
			AntiEvasionSuffix: configuration.Pattern{
				Unix:    "_av-u-suffix_",
				Windows: "_av-w-suffix_",
			},
			AntiEvasionNoSpaceSuffix: configuration.Pattern{
				Unix:    "_av-ns-u-suffix_",
				Windows: "_av-ns-w-suffix_",
			},
		},
	}
}

func TestRunCmdLineTestSuite(t *testing.T) {
	suite.Run(t, new(cmdLineTestSuite))
}

func (s *cmdLineTestSuite) TestCmdLine_NewParser() {
	patterns := s.ctx.rootContext.Configuration().Patterns
	expected := &CmdLine{
		proc: &Processor{
			ctx:   s.ctx,
			lines: []string{},
		},
		cmdType: CmdLineUnix,
		evasionPatterns: map[EvasionPatterns]string{
			evasionPattern:        patterns.AntiEvasion.Unix,
			suffixPattern:         patterns.AntiEvasionSuffix.Unix,
			suffixExpandedCommand: patterns.AntiEvasionNoSpaceSuffix.Unix,
		},
	}
	actual := NewCmdLine(s.ctx, CmdLineUnix)

	s.Equal(expected, actual)
}

func (s *cmdLineTestSuite) TestCmdLine_CmdLineTypeFromString() {
	t, err := CmdLineTypeFromString("unix")
	s.Require().NoError(err)
	cmd := NewCmdLine(s.ctx, t)

	err = cmd.ProcessLine(`foo`)
	s.Require().NoError(err)
	s.Equal(`f_av-u_o_av-u_o`, cmd.proc.lines[0])

	t, err = CmdLineTypeFromString("windows")
	s.Require().NoError(err)
	cmd = NewCmdLine(s.ctx, t)

	err = cmd.ProcessLine(`foo`)
	s.Require().NoError(err)
	s.Equal(`f_av-w_o_av-w_o`, cmd.proc.lines[0])
}

func (s *cmdLineTestSuite) TestCmdLine_BadCmdLineTypeFromString() {
	t, err := CmdLineTypeFromString("nonexistent")
	s.EqualError(err, "bad cmdline option", "cmdline was created even when a bad option was passed")
	s.Equal(t, CmdLineUndefined)
}

func (s *cmdLineTestSuite) TestCmdLine_ProcessLineFoo() {
	cmd := NewCmdLine(s.ctx, CmdLineUnix)

	err := cmd.ProcessLine(`foo`)

	s.Require().NoError(err)
	s.Equal(`f_av-u_o_av-u_o`, cmd.proc.lines[0])
}

func (s *cmdLineTestSuite) TestCmdLine_ProcessLineWithDash() {
	cmd := NewCmdLine(s.ctx, CmdLineUnix)

	err := cmd.ProcessLine(`gcc10\-`)
	s.Require().NoError(err)

	s.Equal(`g_av-u_c_av-u_c_av-u_1_av-u_0_av-u_\-`, cmd.proc.lines[0])

	err = cmd.ProcessLine(`gcc\-10`)
	s.Require().NoError(err)

	s.Equal(`g_av-u_c_av-u_c_av-u_\-_av-u_1_av-u_0`, cmd.proc.lines[1])
}

func (s *cmdLineTestSuite) TestCmdLine_ProcessLineWithDot() {
	cmd := NewCmdLine(s.ctx, CmdLineUnix)

	err := cmd.ProcessLine(`gcc10\.`)
	s.Require().NoError(err)

	s.Equal(`g_av-u_c_av-u_c_av-u_1_av-u_0_av-u_\.`, cmd.proc.lines[0])

	err = cmd.ProcessLine(`gcc\.10`)
	s.Require().NoError(err)

	s.Equal(`g_av-u_c_av-u_c_av-u_\._av-u_1_av-u_0`, cmd.proc.lines[1])
}

func (s *cmdLineTestSuite) TestCmdLine_ProcessLineWithPlus() {
	cmd := NewCmdLine(s.ctx, CmdLineUnix)

	err := cmd.ProcessLine(`gcc10\+`)
	s.Require().NoError(err)

	s.Equal(`g_av-u_c_av-u_c_av-u_1_av-u_0_av-u_\+`, cmd.proc.lines[0])

	err = cmd.ProcessLine(`gcc\+10`)
	s.Require().NoError(err)

	s.Equal(`g_av-u_c_av-u_c_av-u_\+_av-u_1_av-u_0`, cmd.proc.lines[1])
}

func (s *cmdLineTestSuite) TestCmdLine_ProcessLineWithSpace() {
	cmd := NewCmdLine(s.ctx, CmdLineUnix)

	err := cmd.ProcessLine(`gcc 10`)
	s.Require().NoError(err)

	s.Equal(`g_av-u_c_av-u_c_av-u_ _av-u_1_av-u_0`, cmd.proc.lines[0])
}

func (s *cmdLineTestSuite) TestCmdLine_ProcessLineWithUnescapedMetaCharacter() {
	cmd := NewCmdLine(s.ctx, CmdLineUnix)

	for _, char := range []byte{'.', '+'} {
		line := "gcc" + string(char) + "10"
		err := cmd.ProcessLine(line)
		s.ErrorContains(err, fmt.Sprintf("found unescaped meta character `%s` in %s", string(char), line))

		line = "gcc10" + string(char)
		err = cmd.ProcessLine(line)
		s.ErrorContains(err, fmt.Sprintf("found unescaped meta character `%s` in %s", string(char), line))
	}
}

func (s *cmdLineTestSuite) TestCmdLine_ProcessLineFooWindows() {
	cmd := NewCmdLine(s.ctx, CmdLineWindows)

	err := cmd.ProcessLine(`foo`)
	s.Require().NoError(err)

	s.Equal(`f_av-w_o_av-w_o`, cmd.proc.lines[0])
}

func (s *cmdLineTestSuite) TestCmdLine_ProcessTildeOnlyAtLineEnd() {
	cmd := NewCmdLine(s.ctx, CmdLineUnix)

	err := cmd.ProcessLine(`~foo`)
	s.Require().NoError(err)

	s.Equal(`~_av-u_f_av-u_o_av-u_o`, cmd.proc.lines[0])

	err = cmd.ProcessLine(`f~oo`)
	s.Require().NoError(err)

	s.Equal(`f_av-u_~_av-u_o_av-u_o`, cmd.proc.lines[1])
}

func (s *cmdLineTestSuite) TestCmdLine_DontTreatTildeSpecialAtLineStart() {
	cmd := NewCmdLine(s.ctx, CmdLineUnix)

	err := cmd.ProcessLine(`\~foo`)
	s.Require().NoError(err)

	s.Equal(`\~_av-u_f_av-u_o_av-u_o`, cmd.proc.lines[0])
}

func (s *cmdLineTestSuite) TestCmdLine_IgnoreEscapedTildeAtLineEnd() {
	cmd := NewCmdLine(s.ctx, CmdLineUnix)

	err := cmd.ProcessLine(`foo\~`)
	s.Require().NoError(err)

	s.Equal(`f_av-u_o_av-u_o_av-u_~`, cmd.proc.lines[0])
}

func (s *cmdLineTestSuite) TestCmdLine_ProcessAtOnlyAtLineEnd() {
	cmd := NewCmdLine(s.ctx, CmdLineUnix)

	err := cmd.ProcessLine(`@foo`)
	s.Require().NoError(err)

	s.Equal(`@_av-u_f_av-u_o_av-u_o`, cmd.proc.lines[0])

	err = cmd.ProcessLine(`f@oo`)
	s.Require().NoError(err)

	s.Equal(`f_av-u_@_av-u_o_av-u_o`, cmd.proc.lines[1])
}

func (s *cmdLineTestSuite) TestCmdLine_DontTreatAtSpecialAtLineStart() {
	cmd := NewCmdLine(s.ctx, CmdLineUnix)

	err := cmd.ProcessLine(`\@foo`)
	s.Require().NoError(err)

	s.Equal(`\@_av-u_f_av-u_o_av-u_o`, cmd.proc.lines[0])
}

func (s *cmdLineTestSuite) TestCmdLine_IgnoreEscapedAtAtLineEnd() {
	cmd := NewCmdLine(s.ctx, CmdLineUnix)

	err := cmd.ProcessLine(`foo\@`)
	s.Require().NoError(err)

	s.Equal(`f_av-u_o_av-u_o_av-u_@`, cmd.proc.lines[0])
}

package processors

import (
	"github.com/stretchr/testify/suite"
	"regexp"
	"testing"
)

type cmdLineTestSuite struct {
	suite.Suite
	ctx *Context
}

func (s *cmdLineTestSuite) SetupTest() {
	s.ctx = NewContext()
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
			evasionPattern:        `[\x5c'\"]*`,
			suffixPattern:         `(?:\s|<|>).*`,
			suffixExpandedCommand: `(?:(?:<|>)|(?:[\w\d._-][\x5c'\"]*)+(?:\s|<|>)).*`,
		},
	}
	actual := NewCmdLine(s.ctx, CmdLineUnix)

	s.Equal(expected, actual)
}

func (s *cmdLineTestSuite) TestCmdLine_CmdLineTypeFromString() {
	t, err := CmdLineTypeFromString("unix")
	s.NoError(err)
	cmd := NewCmdLine(s.ctx, t)

	cmd.ProcessLine(`foo`)
	s.Equal(`f[\x5c'\"]*o[\x5c'\"]*o`, cmd.proc.lines[0])

	t, err = CmdLineTypeFromString("windows")
	s.NoError(err)
	cmd = NewCmdLine(s.ctx, t)

	cmd.ProcessLine(`foo`)
	s.Equal(`f[\"\^]*o[\"\^]*o`, cmd.proc.lines[0])
}

func (s *cmdLineTestSuite) TestCmdLine_BadCmdLineTypeFromString() {
	t, err := CmdLineTypeFromString("nonexistent")
	s.EqualError(err, "bad cmdline option", "cmdline was created even when a bad option was passed")
	s.Equal(t, CmdLineUndefined)
}

func (s *cmdLineTestSuite) TestCmdLine_ProcessLineFoo() {
	cmd := NewCmdLine(s.ctx, CmdLineUnix)

	cmd.ProcessLine(`foo`)

	s.Equal(`f[\x5c'\"]*o[\x5c'\"]*o`, cmd.proc.lines[0])
}

func (s *cmdLineTestSuite) TestCmdLine_ProcessLinePattern() {
	cmd := NewCmdLine(s.ctx, CmdLineUnix)

	cmd.ProcessLine(`gcc-10.`)

	s.Equal(`g[\x5c'\"]*c[\x5c'\"]*c[\x5c'\"]*\-[\x5c'\"]*1[\x5c'\"]*0[\x5c'\"]*\.`, cmd.proc.lines[0])
}

func (s *cmdLineTestSuite) TestCmdLine_ProcessLineFooWindows() {
	cmd := NewCmdLine(s.ctx, CmdLineWindows)

	cmd.ProcessLine(`foo`)

	s.Equal(`f[\x5c'\"]*o[\x5c'\"]*o`, cmd.proc.lines[0])
}

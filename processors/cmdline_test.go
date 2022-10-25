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
	expected := &Cmdline{
		proc: &Processor{
			ctx:          s.ctx,
			commentRegex: regexp.MustCompile(`^##!`),
			lines:        []string{},
		},
		input:   regexp.MustCompile(AssembleInput),
		output:  regexp.MustCompile(AssembleOutput),
		cmdType: Unix,
		evasion_patterns: map[EvasionPatterns]string{
			EvasionPattern:        `[\x5c'\"]*`,
			SuffixPattern:         `(?:\s|<|>).*`,
			SuffixExpandedCommand: `(?:(?:<|>)|(?:[\w\d._-][\x5c'\"]*)+(?:\s|<|>)).*`,
		},
	}
	actual := NewCmdline(s.ctx, Unix)

	s.Equal(expected, actual)
}

func (s *cmdLineTestSuite) TestCmdLine_ProcessLineFoo() {
	cmd := NewCmdline(s.ctx, Unix)

	cmd.ProcessLine(`foo`)

	s.Equal(`f[\x5c'\"]*o[\x5c'\"]*o`, cmd.proc.lines[0])
}

func (s *cmdLineTestSuite) TestCmdLine_ProcessLinePattern() {
	cmd := NewCmdline(s.ctx, Unix)

	cmd.ProcessLine(`gcc-10.`)

	s.Equal(`g[\x5c'\"]*c[\x5c'\"]*c[\x5c'\"]*\-[\x5c'\"]*1[\x5c'\"]*0[\x5c'\"]*\.`, cmd.proc.lines[0])
}

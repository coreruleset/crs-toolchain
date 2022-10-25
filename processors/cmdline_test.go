package processors

import (
	"github.com/stretchr/testify/suite"
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
			commentRegex: nil,
			lines:        nil,
		},
		input:            nil,
		output:           nil,
		cmdType:          Unix,
		evasion_patterns: nil,
	}
	actual := NewCmdline(s.ctx, Unix)

	s.Equal(expected, actual)
}

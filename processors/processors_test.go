package processors

import (
	"github.com/stretchr/testify/suite"
	"testing"
)

type processorTestSuite struct {
	suite.Suite
	ctx *Context
}

func (s *processorTestSuite) SetupTest() {
	s.ctx = NewContext()
}

func TestRunProcessorTestSuite(t *testing.T) {
	suite.Run(t, new(processorTestSuite))
}

func (s *processorTestSuite) TestProcessor_New() {
	expected := &Processor{
		ctx:   s.ctx,
		lines: []string{},
	}

	actual := NewProcessor()
	s.Equal(expected, actual)
}

func (s *processorTestSuite) TestProcessor_NewWithContext() {
	expected := &Processor{
		ctx:   s.ctx,
		lines: []string{},
	}

	actual := NewProcessorWithContext(s.ctx)
	s.Equal(expected, actual)
}

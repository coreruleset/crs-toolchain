package operators

import (
	"fmt"
)

// Stats are used by preprocessors to track indentation levels and count lines.
type Stats struct {
	line  int
	depth int
}

// NewStats creates a new Stats.
func NewStats() *Stats {
	return &Stats{
		line:  0,
		depth: 0,
	}
}

// ProcessorStart increments the indentation level caused to entering a new Preprocessor.
func (s *Stats) ProcessorStart() {
	s.depth += 1
}

// ProcessorEnd decrements the indentation level caused by leaving a preprocessor. Returns an error if we went too far.
func (s *Stats) ProcessorEnd() error {
	s.depth -= 1
	if s.depth < 0 {
		return fmt.Errorf("nesting error on line %d, nesting level %d", s.line, s.depth)
	}
	return nil
}

// LineParsed increments the lines parsed counter.
func (s *Stats) LineParsed() {
	s.line += 1
}

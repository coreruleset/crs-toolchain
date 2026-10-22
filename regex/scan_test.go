// Copyright 2026 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package regex

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

type scanTestSuite struct {
	suite.Suite
}

func TestRunScanTestSuite(t *testing.T) {
	suite.Run(t, new(scanTestSuite))
}

func (s *scanTestSuite) TestScanGroups() {
	topPipes, groups, ok := ScanGroups(`a|(?:b|c)(d)`)
	s.True(ok)
	s.Equal([]int{1}, topPipes)
	s.Equal([]Group{{Start: 2, End: 9, Pipes: []int{6}}, {Start: 9, End: 12}}, groups)
}

func (s *scanTestSuite) TestScanGroups_Nested() {
	_, groups, ok := ScanGroups(`(?:a(?:b|c))`)
	s.True(ok)
	s.Equal([]Group{{Start: 4, End: 11, Pipes: []int{8}}, {Start: 0, End: 12}}, groups)
	s.True(groups[1].IsOutermost(groups))
	s.False(groups[0].IsOutermost(groups))
}

func (s *scanTestSuite) TestScanGroups_SkipsEscapesClassesAndDefinitions() {
	for _, line := range []string{`a\|b`, `a\(b`, `[|(]c`, `[]|]d`, `[^]|]e`, `[[:alpha:]|]f`, `[a\]|b]g`, `[\]|]h`, `[^\]|]i`, `{{a|b}}k`} {
		topPipes, groups, ok := ScanGroups(line)
		s.True(ok, line)
		s.Empty(topPipes, line)
		s.Empty(groups, line)
	}
}

func (s *scanTestSuite) TestScanGroups_Unbalanced() {
	for _, line := range []string{`(a`, `a)`, `[a`, `[[:alpha:]`, `{{a`} {
		_, _, ok := ScanGroups(line)
		s.False(ok, line)
	}
}

func (s *scanTestSuite) TestClassEnd() {
	s.Equal(2, ClassEnd(`[a]`, 0))
	s.Equal(2, ClassEnd(`[]]`, 0))
	s.Equal(3, ClassEnd(`[^]]`, 0))
	s.Equal(4, ClassEnd(`[a\]]`, 0))
	s.Equal(3, ClassEnd(`[\]]`, 0))
	s.Equal(4, ClassEnd(`[^\]]`, 0))
	s.Equal(3, ClassEnd(`[\\]`, 0))
	s.Equal(10, ClassEnd(`[[:alpha:]]`, 0))
	s.Equal(12, ClassEnd(`[[:alpha:]\]]`, 0))
	s.Equal(4, ClassEnd(`ab[c]d`, 2))
	s.Equal(-1, ClassEnd(`[a`, 0))
	s.Equal(-1, ClassEnd(`[a\]`, 0))
}

func (s *scanTestSuite) TestIsToken() {
	for _, token := range []string{`a`, `\W`, `^`, `[<=>]`, `[]]`, `[a\]]`, `{{quotes}}`} {
		s.True(IsToken(token), token)
	}
	for _, token := range []string{``, `ab`, `\Wa`, `[a]b`, `{{a}}b`} {
		s.False(IsToken(token), token)
	}
}

func (s *scanTestSuite) TestExpandable() {
	expandable := func(line string) bool {
		_, groups, ok := ScanGroups(line)
		s.True(ok, line)
		s.Len(groups, 1, line)
		return groups[0].Expandable(line)
	}
	s.True(expandable(`a(?:b|c)d`))
	s.True(expandable(`a(?:b|c)`))
	s.True(expandable(`(?:b|c){{d}}`))
	s.False(expandable(`a(b|c)d`))
	s.False(expandable(`a(?=b|c)d`))
	s.False(expandable(`a(?:b|c)?d`))
	s.False(expandable(`a(?:b|c)*d`))
	s.False(expandable(`a(?:b|c)+d`))
	s.False(expandable(`a(?:b|c){2}d`))
}

func (s *scanTestSuite) TestAlternatives() {
	line := `a(?:b|cc|)d`
	_, groups, ok := ScanGroups(line)
	s.True(ok)
	s.Equal([]string{"b", "cc", ""}, groups[0].Alternatives(line))
	s.Equal([]string{"a", "b"}, SplitAt("a|b", 0, 3, []int{1}))
	s.Equal([]string{"a|b"}, SplitAt("a|b", 0, 3, nil))
}

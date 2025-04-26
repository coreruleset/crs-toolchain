// Copyright 2025 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

type fpFinderTestSuite struct {
	suite.Suite
}

func (s *fpFinderTestSuite) SetupTest() {
}

func TestRunFpFinderTestSuite(t *testing.T) {
	suite.Run(t, new(fpFinderTestSuite))
}

func (s *fpFinderTestSuite) TestFpFinder_FilterContent() {
	input := []string{
		"# this is a comment",
		" # this is another comment with a space in front",
		"apple", "banana", "apple", "",
	}

	dict := map[string]struct{}{
		"apple": {},
		"dog":   {},
	}

	expected := []string{"banana"}

	result := NewFpFinder().filterContent(input, dict, 3)
	s.Equal(expected, result)
}

func (s *fpFinderTestSuite) TestFpFinder_ProcessWords() {
	input := []string{"apple", "banana", "orange", "banana", "pear", "#comment", "banana"}
	dict := map[string]struct{}{
		"apple":  {},
		"orange": {},
	}

	expected := []string{"banana", "pear"}

	result := NewFpFinder().processWords(input, dict, 3)

	s.Equal(expected, result)
}

func (s *fpFinderTestSuite) TestFpFinder_MergeDictionaries() {
	a := map[string]struct{}{"apple": {}, "banana": {}}
	b := map[string]struct{}{"cherry": {}, "date": {}}

	expected := map[string]struct{}{
		"apple":  {},
		"banana": {},
		"cherry": {},
		"date":   {},
	}

	result := NewFpFinder().mergeDictionaries(a, b)
	s.Equal(expected, result)
}

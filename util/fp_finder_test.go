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

func (s *fpFinderTestSuite) TestFpFinder_Removeduplicates() {
	input := []string{"apple", "banana", "apple", "orange", "banana"}
	expected := []string{"apple", "banana", "orange"}

	result := NewFpFinder().removeDuplicates(input)

	s.Equal(expected, result)
}

func (s *fpFinderTestSuite) TestFpFinder_FilterContent() {
	input := []string{
		"# this is a comment",
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

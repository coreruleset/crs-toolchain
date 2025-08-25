// Copyright 2025 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"testing"

	"github.com/lloyd/wnram"
	"github.com/stretchr/testify/suite"
)

// mockWordNet is a fake implementation of WordNet
type mockWordNet struct {
	lookup map[string][]wnram.Lookup
}

func (m *mockWordNet) Lookup(criteria wnram.Criteria) ([]wnram.Lookup, error) {
	if v, ok := m.lookup[criteria.Matching]; ok {
		return v, nil
	}
	return nil, nil
}

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

	extendedDict := map[string]struct{}{}
	mockWN := &mockWordNet{
		lookup: map[string][]wnram.Lookup{
			"apple": {{}}, // fake lookup result
		},
	}
	expected := []string{"banana"}

	result := NewFpFinder().filterContent(input, mockWN, extendedDict, 3)
	s.Equal(expected, result)
}

func (s *fpFinderTestSuite) TestFpFinder_ProcessWords() {
	input := []string{"apple", "banana", "orange", "banana", "pear", "#comment", "banana"}

	extendedDict := map[string]struct{}{
		"orange": {},
	}
	mockWN := &mockWordNet{
		lookup: map[string][]wnram.Lookup{
			"apple": {{}}, // fake lookup result
		},
	}

	expected := []string{"banana", "pear"}

	result := NewFpFinder().processWords(input, mockWN, extendedDict, 3)

	s.Equal(expected, result)
}

func (s *fpFinderTestSuite) TestFpFinder_ProcessWords_Sorting() {
	input := []string{"pear", "Banana", ".hiddenfruit", "kiwi", "banana", "Apple", ".dotfruit"}

	extendedDict := map[string]struct{}{}
	mockWN := &mockWordNet{
		lookup: map[string][]wnram.Lookup{
			"": {{}}, // fake lookup result
		},
	}

	expected := []string{".dotfruit", ".hiddenfruit", "Apple", "Banana", "banana", "kiwi", "pear"}

	result := NewFpFinder().processWords(input, mockWN, extendedDict, 3)

	s.Equal(expected, result)
}

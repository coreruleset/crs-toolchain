// Copyright 2025 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/coreruleset/wnram"
	"github.com/stretchr/testify/suite"
)

// minimalDataNoun is a single self-contained WordNet noun entry: offset,
// lexicographer file number, part of speech, a one-word hex count, the word
// "entity" with sense 0, a zero pointer count, and a gloss. It deliberately
// declares no relations so it loads without referencing other offsets.
const minimalDataNoun = "00001740 03 n 01 entity 0 000 | a self contained test entry\n"

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

func (s *fpFinderTestSuite) TestDictionaryCacheKey_DiffersByAssetName() {
	// Regression test: a release can gain, lose, or rename assets without its
	// tag changing. The cache key must depend on the asset name too, or a
	// stale, differently-formatted dictionary cached under an older matching
	// asset would silently keep being reused for the same tag.
	same := dictionaryCacheKey("2025-edition", "english-wordnet-2025.zip")
	different := dictionaryCacheKey("2025-edition", "english-wordnet-2025-index.sense-fixed.zip")

	s.NotEqual(same, different)
}

func (s *fpFinderTestSuite) TestDictionaryCacheKey_Stable() {
	first := dictionaryCacheKey("2025-edition", "english-wordnet-2025.zip")
	second := dictionaryCacheKey("2025-edition", "english-wordnet-2025.zip")

	s.Equal(first, second)
}

func (s *fpFinderTestSuite) TestValidateDictionary_ValidDictionary() {
	dir := s.T().TempDir()
	s.Require().NoError(os.WriteFile(filepath.Join(dir, "data.noun"), []byte(minimalDataNoun), 0644))

	s.NoError(validateDictionary(dir))
}

func (s *fpFinderTestSuite) TestValidateDictionary_MissingPath() {
	// A path that was never created must not validate.
	s.Error(validateDictionary(filepath.Join(s.T().TempDir(), "does-not-exist")))
}

func (s *fpFinderTestSuite) TestValidateDictionary_EmptyDirectory() {
	// Regression test: wnram.New succeeds on a directory with no data files, so
	// an empty (e.g. freshly created but not yet populated) directory must be
	// rejected as containing no entries, or a broken download would be cached
	// and reused as if valid.
	s.ErrorContains(validateDictionary(s.T().TempDir()), "no entries")
}

func (s *fpFinderTestSuite) TestValidateDictionary_NoDataFiles() {
	// Regression test: a partially-extracted download may leave unrelated files
	// behind without any WordNet data files. That must not pass validation.
	dir := s.T().TempDir()
	s.Require().NoError(os.WriteFile(filepath.Join(dir, "notadata.txt"), []byte("junk"), 0644))

	s.ErrorContains(validateDictionary(dir), "no entries")
}

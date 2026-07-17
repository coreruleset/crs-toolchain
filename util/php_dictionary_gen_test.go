// Copyright 2025 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/coreruleset/wnram"
	"github.com/stretchr/testify/suite"
)

type phpDictionaryGenTestSuite struct {
	suite.Suite
	gen *PhpDictionaryGen
}

func TestRunPhpDictionaryGenTestSuite(t *testing.T) {
	suite.Run(t, new(phpDictionaryGenTestSuite))
}

func (s *phpDictionaryGenTestSuite) SetupTest() {
	s.gen = NewPhpDictionaryGen()
}

// mockSearcher is a fake GitHubSearcher for testing
type mockSearcher struct {
	counts map[string]int
}

func (m *mockSearcher) SearchCodeCount(_ context.Context, functionName string) (int, error) {
	if count, ok := m.counts[functionName]; ok {
		return count, nil
	}
	return 0, nil
}

// rateLimitThenSuccessSearcher returns a rate-limit error on the first call
// and succeeds on every call after, to test getOrUpdateFrequency's retry.
type rateLimitThenSuccessSearcher struct {
	calls      int
	retryAfter time.Duration
	finalCount int
}

func (s *rateLimitThenSuccessSearcher) SearchCodeCount(_ context.Context, functionName string) (int, error) {
	s.calls++
	if s.calls == 1 {
		return 0, &rateLimitError{functionName: functionName, statusCode: 429, retryAfter: s.retryAfter, hasRetryAfter: true}
	}
	return s.finalCount, nil
}

// rateLimitNoWaitSearcher always returns a rate-limit error with no usable
// wait hint, to verify getOrUpdateFrequency does not retry blindly.
type rateLimitNoWaitSearcher struct {
	calls int
}

func (s *rateLimitNoWaitSearcher) SearchCodeCount(_ context.Context, functionName string) (int, error) {
	s.calls++
	return 0, &rateLimitError{functionName: functionName, statusCode: 403}
}

func (s *phpDictionaryGenTestSuite) TestExtractFunctions_BasicCase() {
	tmpDir := s.T().TempDir()

	// Create a fake PHP source file with ZEND_FUNCTION macros.
	// PHP_FUNCTION lines are intentionally included to verify they are NOT matched.
	// array_map is declared via ZEND_FUNCTION twice (as php-src does across
	// multiple source files) to exercise deduplication.
	src := `
PHP_FUNCTION(array_map)
PHP_FUNCTION(preg_match)
ZEND_FUNCTION(array_filter)
ZEND_FUNCTION(strpos)
ZEND_FUNCTION(array_map)
ZEND_FUNCTION(array_map)
`
	err := os.WriteFile(filepath.Join(tmpDir, "test.c"), []byte(src), fs.ModePerm)
	s.Require().NoError(err)

	functions, err := s.gen.ExtractFunctions(tmpDir)
	s.Require().NoError(err)

	// Should contain the ZEND_FUNCTION names, deduplicated and sorted
	s.Contains(functions, "array_filter")
	s.Contains(functions, "strpos")
	// PHP_FUNCTION macros should not be matched
	s.NotContains(functions, "preg_match", "PHP_FUNCTION should not be matched")
	// array_map appears twice in ZEND_FUNCTION but should only be in the result once
	count := 0
	for _, f := range functions {
		if f == "array_map" {
			count++
		}
	}
	s.Equal(1, count, "array_map should appear exactly once (deduplicated)")
}

func (s *phpDictionaryGenTestSuite) TestExtractFunctions_SkipsMacroDefinition() {
	tmpDir := s.T().TempDir()

	// Zend/zend_API.h defines ZEND_FUNCTION as a macro; this line must not be
	// mistaken for a real function declaration (which would otherwise extract
	// the bogus function name "name").
	src := "#define ZEND_FUNCTION(name) ZEND_NAMED_FUNCTION(zif_##name)\nZEND_FUNCTION(array_filter)\n"
	err := os.WriteFile(filepath.Join(tmpDir, "test.h"), []byte(src), fs.ModePerm)
	s.Require().NoError(err)

	functions, err := s.gen.ExtractFunctions(tmpDir)
	s.Require().NoError(err)

	s.Contains(functions, "array_filter")
	s.NotContains(functions, "name", "macro definition should not be treated as a function declaration")
}

func (s *phpDictionaryGenTestSuite) TestExtractFunctions_SkipsDollarSign() {
	tmpDir := s.T().TempDir()

	// Lines with $ should be skipped
	src := `
ZEND_FUNCTION(valid_function)
ZEND_FUNCTION($invalid)
ZEND_FUNCTION(another_valid)
`
	err := os.WriteFile(filepath.Join(tmpDir, "test.c"), []byte(src), fs.ModePerm)
	s.Require().NoError(err)

	functions, err := s.gen.ExtractFunctions(tmpDir)
	s.Require().NoError(err)

	s.Contains(functions, "valid_function")
	s.Contains(functions, "another_valid")
	for _, f := range functions {
		s.NotContains(f, "$", "function names with $ should be excluded")
	}
}

func (s *phpDictionaryGenTestSuite) TestExtractFunctions_OnlyCSrcFiles() {
	tmpDir := s.T().TempDir()

	cSrc := "ZEND_FUNCTION(from_c_file)\n"
	phpSrc := "ZEND_FUNCTION(from_php_file)\n"

	err := os.WriteFile(filepath.Join(tmpDir, "test.c"), []byte(cSrc), fs.ModePerm)
	s.Require().NoError(err)
	err = os.WriteFile(filepath.Join(tmpDir, "test.php"), []byte(phpSrc), fs.ModePerm)
	s.Require().NoError(err)

	functions, err := s.gen.ExtractFunctions(tmpDir)
	s.Require().NoError(err)

	s.Contains(functions, "from_c_file")
	s.NotContains(functions, "from_php_file")
}

func (s *phpDictionaryGenTestSuite) TestExtractFunctions_IsSorted() {
	tmpDir := s.T().TempDir()

	src := "ZEND_FUNCTION(zebra)\nZEND_FUNCTION(apple)\nZEND_FUNCTION(mango)\n"
	err := os.WriteFile(filepath.Join(tmpDir, "test.c"), []byte(src), fs.ModePerm)
	s.Require().NoError(err)

	functions, err := s.gen.ExtractFunctions(tmpDir)
	s.Require().NoError(err)

	s.Equal([]string{"apple", "mango", "zebra"}, functions)
}

func (s *phpDictionaryGenTestSuite) TestClassifyFunctions() {
	// "apple" is in WordNet (English word), "preg_match" is not
	mockWN := &mockWordNet{
		lookup: map[string][]wnram.Lookup{
			"apple": {{}},
		},
	}

	functions := []string{"apple", "preg_match", "array_map"}
	english, nonEnglish := s.gen.classifyFunctions(functions, mockWN)

	s.Contains(english, "apple")
	s.NotContains(nonEnglish, "apple")
	s.Contains(nonEnglish, "preg_match")
	s.Contains(nonEnglish, "array_map")
}

func (s *phpDictionaryGenTestSuite) TestWriteDataFile() {
	tmpDir := s.T().TempDir()
	outPath := filepath.Join(tmpDir, "test.data")

	functions := []string{"array_map", "preg_match", "strpos"}
	err := s.gen.writeDataFile(outPath, functions, DefaultFrequencyLimit, DefaultAgeLimitDays)
	s.Require().NoError(err)

	content, err := os.ReadFile(outPath)
	s.Require().NoError(err)

	s.Contains(string(content), "array_map")
	s.Contains(string(content), "preg_match")
	s.Contains(string(content), "strpos")
	s.Contains(string(content), "##!")
}

func (s *phpDictionaryGenTestSuite) TestPartitionRareFunctionsAlphabetically_BucketsByFirstLetter() {
	functions := []string{"accel_chdir", "krsort", "quotemeta", "rad2deg", "zend_version"}
	buckets := partitionRareFunctionsAlphabetically(functions, rareWordRanges)

	s.Require().Len(buckets, 3)
	s.Equal(Rule933151FileName, buckets[0].fileName)
	s.Equal([]string{"accel_chdir"}, buckets[0].functions)
	s.Equal(Rule933152FileName, buckets[1].fileName)
	s.Equal([]string{"krsort", "quotemeta"}, buckets[1].functions)
	s.Equal(Rule933153FileName, buckets[2].fileName)
	s.Equal([]string{"rad2deg", "zend_version"}, buckets[2].functions)
}

func (s *phpDictionaryGenTestSuite) TestPartitionRareFunctionsAlphabetically_CaseInsensitive() {
	// Uppercase-leading names (e.g. Zend test-suite helpers) should bucket the
	// same as their lowercased first letter.
	functions := []string{"ZendTestNS2_namespaced_func", "Apple"}
	buckets := partitionRareFunctionsAlphabetically(functions, rareWordRanges)

	s.Equal([]string{"Apple"}, buckets[0].functions, "a-j bucket")
	s.Empty(buckets[1].functions, "k-q bucket")
	s.Equal([]string{"ZendTestNS2_namespaced_func"}, buckets[2].functions, "r-z bucket")
}

func (s *phpDictionaryGenTestSuite) TestWriteIncludeWordListFile() {
	tmpDir := s.T().TempDir()
	outPath := filepath.Join(tmpDir, "php-function-names-933151.ra")

	functions := []string{"accel_chdir", "acos"}
	err := s.gen.writeIncludeWordListFile(outPath, functions, DefaultFrequencyLimit, DefaultAgeLimitDays,
		"a-j", "php-function-names-933152.ra and php-function-names-933153.ra")
	s.Require().NoError(err)

	content, err := os.ReadFile(outPath)
	s.Require().NoError(err)

	contentStr := string(content)
	s.Contains(contentStr, "accel_chdir")
	s.Contains(contentStr, "acos")
	s.Contains(contentStr, "##! Please refer to the documentation at")
	s.Contains(contentStr, "##! File autogenerated by crs-toolchain util php-dictionary-gen with: -a 30 -F 90000")
	s.Contains(contentStr, "##! This file only includes words which start with a-j. "+
		"See php-function-names-933152.ra and php-function-names-933153.ra.")
}

func (s *phpDictionaryGenTestSuite) TestWriteAssemblyFile() {
	tmpDir := s.T().TempDir()
	outPath := filepath.Join(tmpDir, "test.ra")

	functions := []string{"echo", "print", "sprintf"}
	err := s.gen.writeAssemblyFile(outPath, functions, DefaultFrequencyLimit, DefaultAgeLimitDays)
	s.Require().NoError(err)

	content, err := os.ReadFile(outPath)
	s.Require().NoError(err)

	contentStr := string(content)
	s.Contains(contentStr, "echo")
	s.Contains(contentStr, "print")
	s.Contains(contentStr, "sprintf")
	s.Contains(contentStr, "##!+ i")
	s.Contains(contentStr, `##!^ \b`)
	s.Contains(contentStr, `##!$ (?:\s|/\*.*\*/|#.*|//.*)*\(.*\)`)
	s.Contains(contentStr, "##! Please refer to the documentation at")
}

func (s *phpDictionaryGenTestSuite) TestLoadAndSaveFrequencyList() {
	tmpDir := s.T().TempDir()
	listPath := filepath.Join(tmpDir, "frequency.txt")

	// Write a frequency list
	cache := map[string]frequencyEntry{
		"array_map":  {count: 150000, updatedAt: mustParseDate("2024-01-15")},
		"preg_match": {count: 50000, updatedAt: mustParseDate("2024-01-15")},
	}
	err := s.gen.saveFrequencyList(listPath, cache)
	s.Require().NoError(err)

	// Load it back
	loaded, err := s.gen.loadFrequencyList(listPath)
	s.Require().NoError(err)

	s.Len(loaded, 2)
	s.Equal(150000, loaded["array_map"].count)
	s.Equal(50000, loaded["preg_match"].count)
}

func (s *phpDictionaryGenTestSuite) TestLoadFrequencyList_NonExistentFile() {
	cache, err := s.gen.loadFrequencyList("/nonexistent/path/frequency.txt")
	s.Require().NoError(err)
	s.Empty(cache)
}

func (s *phpDictionaryGenTestSuite) TestGetOrUpdateFrequency_UsesCache() {
	cache := map[string]frequencyEntry{
		"array_map": {count: 200000, updatedAt: mustParseDate("2099-01-01")},
	}
	searcher := &mockSearcher{counts: map[string]int{"array_map": 999}}

	count, err := s.gen.getOrUpdateFrequency(context.Background(), "array_map", cache, searcher, 30*24*time.Hour, "2099-01-02")
	s.Require().NoError(err)

	// Should use cached value, not call searcher
	s.Equal(200000, count)
}

func (s *phpDictionaryGenTestSuite) TestGetOrUpdateFrequency_FetchesWhenMissing() {
	cache := map[string]frequencyEntry{}
	searcher := &mockSearcher{counts: map[string]int{"array_map": 150000}}

	count, err := s.gen.getOrUpdateFrequency(context.Background(), "array_map", cache, searcher, 30*24*time.Hour, "2024-01-15")
	s.Require().NoError(err)

	s.Equal(150000, count)
	s.Equal(150000, cache["array_map"].count)
}

func (s *phpDictionaryGenTestSuite) TestGetOrUpdateFrequency_RetriesOnRateLimit() {
	cache := map[string]frequencyEntry{}
	searcher := &rateLimitThenSuccessSearcher{retryAfter: time.Millisecond, finalCount: 42}

	count, err := s.gen.getOrUpdateFrequency(context.Background(), "array_map", cache, searcher, 30*24*time.Hour, "2024-01-15")
	s.Require().NoError(err)

	s.Equal(42, count)
	s.Equal(2, searcher.calls, "should retry once after a rate-limit error with a wait hint")
}

func (s *phpDictionaryGenTestSuite) TestGetOrUpdateFrequency_RateLimitWithoutWaitHint_DoesNotRetry() {
	cache := map[string]frequencyEntry{}
	searcher := &rateLimitNoWaitSearcher{}

	_, err := s.gen.getOrUpdateFrequency(context.Background(), "array_map", cache, searcher, 30*24*time.Hour, "2024-01-15")

	s.Error(err)
	s.Equal(1, searcher.calls, "should not retry blindly when no wait hint is available")
}

func (s *phpDictionaryGenTestSuite) TestGetOrUpdateFrequency_ContextCancelledDuringRateLimitWait() {
	cache := map[string]frequencyEntry{}
	searcher := &rateLimitThenSuccessSearcher{retryAfter: time.Hour, finalCount: 42}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := s.gen.getOrUpdateFrequency(ctx, "array_map", cache, searcher, 30*24*time.Hour, "2024-01-15")

	s.ErrorIs(err, context.Canceled)
	s.Equal(1, searcher.calls, "should not retry once the context is cancelled")
}

func mustParseDate(s string) time.Time {
	t, _ := time.Parse(frequencyListDateFormat, s)
	return t
}

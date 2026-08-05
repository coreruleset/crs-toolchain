// Copyright 2025 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"context"
	"errors"
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

func defaultOptions() PhpDictionaryGenOptions {
	return applyDefaults(PhpDictionaryGenOptions{})
}

func (s *phpDictionaryGenTestSuite) TestBuildRareWordRanges_SeeAlsoUsesConfiguredFileNames() {
	opts := defaultOptions()
	opts.Rule933151FileName = "custom-a-j.ra"
	opts.Rule933152FileName = "custom-k-q.ra"
	opts.Rule933153FileName = "custom-r-z.ra"

	ranges := buildRareWordRanges(opts)

	s.Require().Len(ranges, 3)
	s.Equal("custom-k-q.ra and custom-r-z.ra", ranges[0].seeAlso)
	s.Equal("custom-a-j.ra and custom-r-z.ra", ranges[1].seeAlso)
	s.Equal("custom-a-j.ra and custom-k-q.ra", ranges[2].seeAlso)
}

func (s *phpDictionaryGenTestSuite) TestPartitionRareFunctionsAlphabetically_BucketsByFirstLetter() {
	functions := []string{"accel_chdir", "krsort", "quotemeta", "rad2deg", "zend_version"}
	ranges := buildRareWordRanges(defaultOptions())
	buckets := partitionRareFunctionsAlphabetically(functions, ranges)

	s.Require().Len(buckets, 3)
	s.Equal(DefaultRule933151FileName, buckets[0].fileName)
	s.Equal([]string{"accel_chdir"}, buckets[0].functions)
	s.Equal(DefaultRule933152FileName, buckets[1].fileName)
	s.Equal([]string{"krsort", "quotemeta"}, buckets[1].functions)
	s.Equal(DefaultRule933153FileName, buckets[2].fileName)
	s.Equal([]string{"rad2deg", "zend_version"}, buckets[2].functions)
}

func (s *phpDictionaryGenTestSuite) TestPartitionRareFunctionsAlphabetically_CaseInsensitive() {
	// Uppercase-leading names (e.g. Zend test-suite helpers) should bucket the
	// same as their lowercased first letter.
	functions := []string{"ZendTestNS2_namespaced_func", "Apple"}
	ranges := buildRareWordRanges(defaultOptions())
	buckets := partitionRareFunctionsAlphabetically(functions, ranges)

	s.Equal([]string{"Apple"}, buckets[0].functions, "a-j bucket")
	s.Empty(buckets[1].functions, "k-q bucket")
	s.Equal([]string{"ZendTestNS2_namespaced_func"}, buckets[2].functions, "r-z bucket")
}

func (s *phpDictionaryGenTestSuite) TestPhpReleaseBranchPattern_MatchesBareAndPatchBranches() {
	// Real branch names observed on github.com/php/php-src.
	cases := map[string][]string{
		"PHP-8.3":        {"8", "3", ""},
		"PHP-8.3.31":     {"8", "3", "31"},
		"PHP-4.2.0":      {"4", "2", "0"},
		"PHP-5.6.39":     {"5", "6", "39"},
		"PHP-7.1.0RC1":   nil, // pre-release suffixes must not match
		"PHP-7.1.0beta1": nil,
		"master":         nil,
	}
	for branch, want := range cases {
		match := phpReleaseBranchPattern.FindStringSubmatch(branch)
		if want == nil {
			s.Nil(match, "branch %s should not match", branch)
			continue
		}
		if s.NotNil(match, "branch %s should match", branch) {
			s.Equal(want, match[1:], "captured groups for %s", branch)
		}
	}
}

func (s *phpDictionaryGenTestSuite) TestSelectReleaseBranches_OldestAndNewestPerMajor() {
	// PHP 5 only ever had 6 minor releases (5.0-5.6); the youngest branch was
	// PHP-5.6, whose final patch was 5.6.39/40. Per theseion's review comment,
	// only 5.0 (oldest) and 5.6 (newest) should be selected.
	releases := []phpRelease{
		{name: "PHP-5.0", major: 5, minor: 0, patch: -1},
		{name: "PHP-5.3", major: 5, minor: 3, patch: -1},
		{name: "PHP-5.6", major: 5, minor: 6, patch: -1},
		{name: "PHP-5.6.39", major: 5, minor: 6, patch: 39},
	}

	branches := selectReleaseBranches(releases, 1)

	s.ElementsMatch([]string{"PHP-5.0", "PHP-5.6"}, branches)
}

func (s *phpDictionaryGenTestSuite) TestSelectReleaseBranches_PatchOnlyMinorIsNotDropped() {
	// Real php-src history: PHP-4.2 never got a bare branch, only patch
	// branches (PHP-4.2.0, PHP-4.2.2). It must still be discovered and used
	// as the newest minor for major 4, represented by its highest patch.
	releases := []phpRelease{
		{name: "PHP-4.0", major: 4, minor: 0, patch: -1},
		{name: "PHP-4.2.0", major: 4, minor: 2, patch: 0},
		{name: "PHP-4.2.2", major: 4, minor: 2, patch: 2},
	}

	branches := selectReleaseBranches(releases, 1)

	s.ElementsMatch([]string{"PHP-4.0", "PHP-4.2.2"}, branches)
}

func (s *phpDictionaryGenTestSuite) TestSelectReleaseBranches_PrefersBareBranchOverPatch() {
	// When a minor has both a bare branch and patch branches, the bare
	// branch is the mutable tip and should be preferred as the freshest code.
	releases := []phpRelease{
		{name: "PHP-8.3.0", major: 8, minor: 3, patch: 0},
		{name: "PHP-8.3.31", major: 8, minor: 3, patch: 31},
		{name: "PHP-8.3", major: 8, minor: 3, patch: -1},
	}

	branches := selectReleaseBranches(releases, 1)

	s.Equal([]string{"PHP-8.3"}, branches)
}

func (s *phpDictionaryGenTestSuite) TestSelectReleaseBranches_SingleMinorNotDuplicated() {
	releases := []phpRelease{
		{name: "PHP-8.0", major: 8, minor: 0, patch: -1},
	}

	branches := selectReleaseBranches(releases, 1)

	s.Equal([]string{"PHP-8.0"}, branches)
}

func (s *phpDictionaryGenTestSuite) TestSelectReleaseBranches_LimitsToMostRecentMajors() {
	releases := []phpRelease{
		{name: "PHP-5.0", major: 5, minor: 0, patch: -1},
		{name: "PHP-5.6", major: 5, minor: 6, patch: -1},
		{name: "PHP-7.0", major: 7, minor: 0, patch: -1},
		{name: "PHP-7.4", major: 7, minor: 4, patch: -1},
		{name: "PHP-8.0", major: 8, minor: 0, patch: -1},
		{name: "PHP-8.3", major: 8, minor: 3, patch: -1},
	}

	branches := selectReleaseBranches(releases, 2)

	// Only major versions 8 and 7 (the 2 most recent) should be considered;
	// major 5 should be dropped entirely.
	s.ElementsMatch([]string{"PHP-8.0", "PHP-8.3", "PHP-7.0", "PHP-7.4"}, branches)
}

func (s *phpDictionaryGenTestSuite) TestSelectReleaseBranches_ZeroOrNegativeCountReturnsNil() {
	releases := []phpRelease{{name: "PHP-8.3", major: 8, minor: 3, patch: -1}}

	s.Nil(selectReleaseBranches(releases, 0))
	s.Nil(selectReleaseBranches(releases, -1))
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
	s.Contains(contentStr, "##! File autogenerated by crs-toolchain generate php-function-names with: -a 30 -F 90000")
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

// alwaysFailsSearcher returns the given error on every call.
type alwaysFailsSearcher struct {
	calls int
	err   error
}

func (s *alwaysFailsSearcher) SearchCodeCount(_ context.Context, _ string) (int, error) {
	s.calls++
	return 0, s.err
}

func defaultLookupParams(ageLimit time.Duration, today string) frequencyLookupParams {
	return frequencyLookupParams{ageLimit: ageLimit, today: today, maxRateLimitWait: time.Minute}
}

func (s *phpDictionaryGenTestSuite) TestGetOrUpdateFrequency_UsesCache() {
	cache := map[string]frequencyEntry{
		"array_map": {count: 200000, updatedAt: mustParseDate("2099-01-01")},
	}
	searcher := &mockSearcher{counts: map[string]int{"array_map": 999}}

	count, err := s.gen.getOrUpdateFrequency(context.Background(), "array_map", cache, searcher,
		defaultLookupParams(30*24*time.Hour, "2099-01-02"))
	s.Require().NoError(err)

	// Should use cached value, not call searcher
	s.Equal(200000, count)
}

func (s *phpDictionaryGenTestSuite) TestGetOrUpdateFrequency_FetchesWhenMissing() {
	cache := map[string]frequencyEntry{}
	searcher := &mockSearcher{counts: map[string]int{"array_map": 150000}}

	count, err := s.gen.getOrUpdateFrequency(context.Background(), "array_map", cache, searcher,
		defaultLookupParams(30*24*time.Hour, "2024-01-15"))
	s.Require().NoError(err)

	s.Equal(150000, count)
	s.Equal(150000, cache["array_map"].count)
}

func (s *phpDictionaryGenTestSuite) TestGetOrUpdateFrequency_RetriesOnRateLimit() {
	cache := map[string]frequencyEntry{}
	searcher := &rateLimitThenSuccessSearcher{retryAfter: time.Millisecond, finalCount: 42}

	count, err := s.gen.getOrUpdateFrequency(context.Background(), "array_map", cache, searcher,
		defaultLookupParams(30*24*time.Hour, "2024-01-15"))
	s.Require().NoError(err)

	s.Equal(42, count)
	s.Equal(2, searcher.calls, "should retry once after a rate-limit error with a wait hint")
}

func (s *phpDictionaryGenTestSuite) TestGetOrUpdateFrequency_RateLimitWithoutWaitHint_DoesNotRetry() {
	cache := map[string]frequencyEntry{}
	searcher := &rateLimitNoWaitSearcher{}

	_, err := s.gen.getOrUpdateFrequency(context.Background(), "array_map", cache, searcher,
		defaultLookupParams(30*24*time.Hour, "2024-01-15"))

	s.Error(err)
	s.Equal(1, searcher.calls, "should not retry blindly when no wait hint is available")
}

func (s *phpDictionaryGenTestSuite) TestGetOrUpdateFrequency_ContextCancelledDuringRateLimitWait() {
	cache := map[string]frequencyEntry{}
	searcher := &rateLimitThenSuccessSearcher{retryAfter: time.Hour, finalCount: 42}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := s.gen.getOrUpdateFrequency(ctx, "array_map", cache, searcher,
		defaultLookupParams(30*24*time.Hour, "2024-01-15"))

	s.ErrorIs(err, context.Canceled)
	s.Equal(1, searcher.calls, "should not retry once the context is cancelled")
}

func (s *phpDictionaryGenTestSuite) TestGetOrUpdateFrequency_NoEntryAndFetchFails_ReturnsUnavailableError() {
	cache := map[string]frequencyEntry{}
	searcher := &alwaysFailsSearcher{err: errors.New("network error")}

	_, err := s.gen.getOrUpdateFrequency(context.Background(), "array_map", cache, searcher,
		defaultLookupParams(30*24*time.Hour, "2024-01-15"))

	var unavailableErr *errFrequencyUnavailable
	s.Require().ErrorAs(err, &unavailableErr)
}

func (s *phpDictionaryGenTestSuite) TestGetOrUpdateFrequency_RenewalFailure_FallsBackToStaleWithinHardLimit() {
	ageLimit := 30 * 24 * time.Hour
	// Stale (past ageLimit) but well within the hard limit (ageLimit * 3).
	cache := map[string]frequencyEntry{
		"array_map": {count: 12345, updatedAt: time.Now().Add(-31 * 24 * time.Hour)},
	}
	searcher := &alwaysFailsSearcher{err: errors.New("network error")}

	count, err := s.gen.getOrUpdateFrequency(context.Background(), "array_map", cache, searcher,
		defaultLookupParams(ageLimit, time.Now().Format(frequencyListDateFormat)))

	s.Require().NoError(err)
	s.Equal(12345, count, "should fall back to the stale cached value")
}

func (s *phpDictionaryGenTestSuite) TestGetOrUpdateFrequency_RenewalFailure_ReturnsErrorBeyondHardLimit() {
	ageLimit := 30 * 24 * time.Hour
	// Older than the hard limit (ageLimit * staleFrequencyHardLimitMultiplier).
	cache := map[string]frequencyEntry{
		"array_map": {count: 12345, updatedAt: time.Now().Add(-(ageLimit*staleFrequencyHardLimitMultiplier + time.Hour))},
	}
	searcher := &alwaysFailsSearcher{err: errors.New("network error")}

	_, err := s.gen.getOrUpdateFrequency(context.Background(), "array_map", cache, searcher,
		defaultLookupParams(ageLimit, time.Now().Format(frequencyListDateFormat)))

	var renewalErr *errFrequencyRenewalExpired
	s.Require().ErrorAs(err, &renewalErr)
}

func mustParseDate(s string) time.Time {
	t, _ := time.Parse(frequencyListDateFormat, s)
	return t
}

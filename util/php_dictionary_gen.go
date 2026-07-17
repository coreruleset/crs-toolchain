// Copyright 2025 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/coreruleset/wnram"
	git "github.com/go-git/go-git/v5"

	crsctx "github.com/coreruleset/crs-toolchain/v2/context"
	"github.com/coreruleset/crs-toolchain/v2/utils"
)

const (
	phpRepoURL              = "https://github.com/php/php-src"
	DefaultFrequencyLimit   = 90000
	DefaultAgeLimitDays     = 30
	Rule933150FileName      = "php-function-names-933150.data"
	Rule933151FileName      = "php-function-names-933151.ra"
	Rule933152FileName      = "php-function-names-933152.ra"
	Rule933153FileName      = "php-function-names-933153.ra"
	Rule933161FileName      = "933161.ra"
	gitHubSearchAPIFormat   = "https://api.github.com/search/code?q=%s+language:php&type=Code&per_page=1"
	gitHubAPIVersion        = "2022-11-28"
	frequencyListDateFormat = "2006-01-02"
	generatorName           = "crs-toolchain util php-dictionary-gen"
	// maxRateLimitWait caps how long getOrUpdateFrequency will sleep before
	// retrying a rate-limited request, in case the server-reported wait time
	// (e.g. X-RateLimit-Reset far in the future) is unexpectedly large.
	maxRateLimitWait = 2 * time.Minute
)

// rateLimitError indicates the GitHub API rate limit was hit while looking up
// functionName. RetryAfter is how long the caller should wait before retrying;
// HasRetryAfter is false when the response didn't include a usable wait hint.
type rateLimitError struct {
	functionName  string
	statusCode    int
	retryAfter    time.Duration
	hasRetryAfter bool
}

func (e *rateLimitError) Error() string {
	return fmt.Sprintf("GitHub API rate limit exceeded for %s (status %d)", e.functionName, e.statusCode)
}

// rareWordRange describes one of the three alphabetical partitions that rule
// 933151 was split into (933151/933152/933153) to work around regex size
// limitations. Bucketing is based on the lowercased first letter of the
// function name.
type rareWordRange struct {
	fileName string
	label    string
	seeAlso  string
	from, to byte
}

var rareWordRanges = []rareWordRange{
	{fileName: Rule933151FileName, label: "a-j", seeAlso: "php-function-names-933152.ra and php-function-names-933153.ra", from: 'a', to: 'j'},
	{fileName: Rule933152FileName, label: "k-q", seeAlso: "php-function-names-933151.ra and php-function-names-933153.ra", from: 'k', to: 'q'},
	{fileName: Rule933153FileName, label: "r-z", seeAlso: "php-function-names-933151.ra and php-function-names-933152.ra", from: 'r', to: 'z'},
}

// rareWordBucket is one alphabetical partition of the rare-function word list,
// ready to be written to its own include file.
type rareWordBucket struct {
	fileName  string
	label     string
	seeAlso   string
	functions []string
}

// partitionRareFunctionsAlphabetically splits functions into the alphabetical
// buckets described by ranges, based on the lowercased first letter of each
// function name.
func partitionRareFunctionsAlphabetically(functions []string, ranges []rareWordRange) []rareWordBucket {
	buckets := make([]rareWordBucket, len(ranges))
	for i, r := range ranges {
		buckets[i] = rareWordBucket{fileName: r.fileName, label: r.label, seeAlso: r.seeAlso}
	}

	for _, fn := range functions {
		if fn == "" {
			continue
		}
		c := fn[0]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		for i, r := range ranges {
			if c >= r.from && c <= r.to {
				buckets[i].functions = append(buckets[i].functions, fn)
				break
			}
		}
	}
	return buckets
}

var zendFunctionRegex = regexp.MustCompile(`ZEND_FUNCTION\(([^$)]+)\)`)

// GitHubSearcher defines the interface for checking PHP function frequency on GitHub.
type GitHubSearcher interface {
	SearchCodeCount(ctx context.Context, functionName string) (int, error)
}

// PhpDictionaryGenOptions contains options for PHP dictionary generation.
type PhpDictionaryGenOptions struct {
	// PhpRepoPath is the path to a local PHP source repository.
	// If empty, the PHP repository will be cloned from GitHub.
	PhpRepoPath string
	// FrequencyLimit is the minimum GitHub occurrence count to qualify for rule 933150.
	// Functions with fewer occurrences will be placed in rules 933151/933152/933153.
	FrequencyLimit int
	// AgeLimitDays is the number of days before a frequency cache entry is considered stale.
	AgeLimitDays int
	// FrequencyListPath is the path to the frequency cache file.
	// If empty, no caching is used.
	FrequencyListPath string
	// Rules is a list of rule IDs to generate (e.g. ["933150", "933151", "933152", "933153", "933161"]).
	// If empty, all supported rules are generated.
	Rules []string
	// GitHubToken is the GitHub API token for authenticated requests.
	// Reads from the GITHUB_TOKEN environment variable if empty.
	GitHubToken string
}

// PhpDictionaryGen generates .data and .ra files for PHP function names.
type PhpDictionaryGen struct{}

// NewPhpDictionaryGen creates a new PhpDictionaryGen instance.
func NewPhpDictionaryGen() *PhpDictionaryGen {
	return &PhpDictionaryGen{}
}

// NewWordNet creates a WordNet instance, downloading the dictionary if needed.
func NewWordNet() (WordNet, error) {
	dictionaryPath, err := utils.GetCacheFilePath(dictionaryBaseFileName)
	if err != nil {
		return nil, fmt.Errorf("getting dictionary path: %w", err)
	}

	if _, err := os.Stat(dictionaryPath); os.IsNotExist(err) {
		logger.Debug().Msg("WordNet dictionary not found. Downloading...")
		dictionaryURL := fmt.Sprintf(dictionaryURLFormat, dictionaryBaseFileName)
		logger.Debug().Msgf("Downloading dictionary from %s to %s", dictionaryURL, dictionaryPath)
		if err := utils.DownloadFile(dictionaryPath, dictionaryURL); err != nil {
			return nil, fmt.Errorf("downloading WordNet dictionary: %w", err)
		}
		logger.Debug().Msg("Download complete.")
	} else {
		logger.Debug().Msg("WordNet dictionary found, skipping download.")
	}

	wn, err := wnram.New(dictionaryPath)
	if err != nil {
		return nil, fmt.Errorf("initializing WordNet: %w", err)
	}
	return wn, nil
}

// frequencyEntry represents a cached frequency entry for a PHP function.
type frequencyEntry struct {
	count     int
	updatedAt time.Time
}

// gitHubSearchClient implements GitHubSearcher using the GitHub search API.
type gitHubSearchClient struct {
	token      string
	httpClient *http.Client
}

func NewGitHubSearchClient(token string) *gitHubSearchClient {
	return &gitHubSearchClient{
		token:      token,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// SearchCodeCount returns the number of GitHub code search results for the given PHP function name.
func (c *gitHubSearchClient) SearchCodeCount(ctx context.Context, functionName string) (int, error) {
	escapedName := url.QueryEscape(functionName)
	apiURL := fmt.Sprintf(gitHubSearchAPIFormat, escapedName)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return 0, fmt.Errorf("creating request for %s: %w", functionName, err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", gitHubAPIVersion)
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("fetching frequency for %s: %w", functionName, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		rlErr := &rateLimitError{functionName: functionName, statusCode: resp.StatusCode}
		// Try to honour the Retry-After header so the caller knows when to retry.
		if retryAfter := resp.Header.Get("Retry-After"); retryAfter != "" {
			if secs, err := strconv.Atoi(retryAfter); err == nil {
				rlErr.retryAfter = time.Duration(secs) * time.Second
				rlErr.hasRetryAfter = true
				logger.Warn().Msgf("GitHub API rate limit hit for %s; retry after %d seconds", functionName, secs)
			}
		} else if resetHeader := resp.Header.Get("X-RateLimit-Reset"); resetHeader != "" {
			if resetUnix, err := strconv.ParseInt(resetHeader, 10, 64); err == nil {
				resetTime := time.Unix(resetUnix, 0)
				if wait := time.Until(resetTime); wait > 0 {
					rlErr.retryAfter = wait
					rlErr.hasRetryAfter = true
				}
				logger.Warn().Msgf("GitHub API rate limit hit for %s; resets at %v", functionName, resetTime)
			}
		} else {
			logger.Warn().Msgf("GitHub API rate limit hit for %s (status %d)", functionName, resp.StatusCode)
		}
		return 0, rlErr
	}
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("unexpected GitHub API status %d for %s", resp.StatusCode, functionName)
	}

	var result struct {
		TotalCount int `json:"total_count"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, fmt.Errorf("decoding GitHub response for %s: %w", functionName, err)
	}

	return result.TotalCount, nil
}

// Generate runs the PHP dictionary generation process.
// It extracts PHP function names from the PHP source, classifies them using
// WordNet, checks their GitHub frequency, and writes the output files to the
// appropriate CRS directories.
// If wn is nil, a WordNet instance is created automatically (downloading the
// dictionary if needed).
func (p *PhpDictionaryGen) Generate(ctx context.Context, ctxt *crsctx.Context, opts PhpDictionaryGenOptions, wn WordNet, searcher GitHubSearcher) error {
	if opts.FrequencyLimit <= 0 {
		opts.FrequencyLimit = DefaultFrequencyLimit
	}
	if opts.AgeLimitDays <= 0 {
		opts.AgeLimitDays = DefaultAgeLimitDays
	}
	rules := opts.Rules
	if len(rules) == 0 {
		rules = []string{"933150", "933151", "933152", "933153", "933161"}
	}

	// Determine which rules to generate
	doRule933150 := slices.Contains(rules, "933150")
	doRule933151 := slices.Contains(rules, "933151")
	doRule933152 := slices.Contains(rules, "933152")
	doRule933153 := slices.Contains(rules, "933153")
	doRule933161 := slices.Contains(rules, "933161")
	// 933151/933152/933153 are three alphabetical partitions of the same
	// "rare function" word list, split to work around regex size limitations.
	doRuleRare := doRule933151 || doRule933152 || doRule933153

	// Initialize WordNet if not provided; it is needed for all rule combinations
	// because classifyFunctions (which separates English/non-English names) is
	// called whenever any rule is being generated.
	if wn == nil && (doRule933161 || doRule933150 || doRuleRare) {
		var err error
		wn, err = NewWordNet()
		if err != nil {
			return fmt.Errorf("initializing WordNet: %w", err)
		}
	}

	// Get PHP source (clone if necessary)
	phpRepoPath := opts.PhpRepoPath
	cleanupTmpDir := ""
	if phpRepoPath == "" {
		tmpDir, err := os.MkdirTemp("", "php-src-")
		if err != nil {
			return fmt.Errorf("creating temp directory for PHP repo: %w", err)
		}
		cleanupTmpDir = tmpDir
		logger.Info().Msgf("Cloning PHP repository from %s", phpRepoURL)
		_, err = git.PlainCloneContext(ctx, tmpDir, false, &git.CloneOptions{
			URL:   phpRepoURL,
			Depth: 1,
		})
		if err != nil {
			os.RemoveAll(cleanupTmpDir)
			return fmt.Errorf("cloning PHP repository: %w", err)
		}
		phpRepoPath = tmpDir
		logger.Info().Msg("PHP repository cloned successfully")
	}
	if cleanupTmpDir != "" {
		defer func() {
			if err := os.RemoveAll(cleanupTmpDir); err != nil {
				logger.Warn().Err(err).Msgf("Failed to clean up temporary PHP repo at %s", cleanupTmpDir)
			}
		}()
	}

	// Extract function names
	logger.Info().Msg("Extracting PHP function names")
	functions, err := p.ExtractFunctions(phpRepoPath)
	if err != nil {
		return fmt.Errorf("extracting PHP function names: %w", err)
	}
	logger.Info().Msgf("Found %d PHP function names", len(functions))

	// Load frequency cache
	var frequencyCache map[string]frequencyEntry
	if opts.FrequencyListPath != "" {
		frequencyCache, err = p.loadFrequencyList(opts.FrequencyListPath)
		if err != nil {
			return fmt.Errorf("loading frequency list: %w", err)
		}
	} else {
		frequencyCache = make(map[string]frequencyEntry)
	}

	// Classify: English words vs. non-English
	logger.Info().Msg("Classifying PHP function names")
	englishWords, nonEnglishWords := p.classifyFunctions(functions, wn)
	logger.Info().Msgf("Found %d English words and %d non-English function names",
		len(englishWords), len(nonEnglishWords))

	// For non-English words: check frequency and categorize
	var frequentFunctions []string
	var rareFunctions []string

	if doRule933150 || doRuleRare {
		today := time.Now().Format(frequencyListDateFormat)
		ageLimitDuration := time.Duration(opts.AgeLimitDays) * 24 * time.Hour

		for _, fn := range nonEnglishWords {
			count, err := p.getOrUpdateFrequency(ctx, fn, frequencyCache, searcher, ageLimitDuration, today)
			if err != nil {
				if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					return fmt.Errorf("frequency lookup for %s interrupted: %w", fn, err)
				}
				logger.Warn().Err(err).Msgf("Failed to get frequency for %s, skipping", fn)
				continue
			}

			if count > opts.FrequencyLimit {
				frequentFunctions = append(frequentFunctions, fn)
			} else {
				rareFunctions = append(rareFunctions, fn)
			}
		}

		// Save updated frequency cache
		if opts.FrequencyListPath != "" {
			if err := p.saveFrequencyList(opts.FrequencyListPath, frequencyCache); err != nil {
				return fmt.Errorf("saving frequency list: %w", err)
			}
		}
	}

	// Sort all output
	slices.Sort(englishWords)
	slices.Sort(frequentFunctions)
	slices.Sort(rareFunctions)

	// Write output files
	if doRule933150 {
		outPath := filepath.Join(ctxt.RulesDir(), Rule933150FileName)
		logger.Info().Msgf("Writing rule 933150 data to %s", outPath)
		if err := p.writeDataFile(outPath, frequentFunctions, opts.FrequencyLimit, opts.AgeLimitDays); err != nil {
			return fmt.Errorf("writing 933150 data file: %w", err)
		}
	}

	if doRuleRare {
		requested := map[string]bool{
			Rule933151FileName: doRule933151,
			Rule933152FileName: doRule933152,
			Rule933153FileName: doRule933153,
		}
		for _, words := range partitionRareFunctionsAlphabetically(rareFunctions, rareWordRanges) {
			if !requested[words.fileName] {
				continue
			}
			outPath := filepath.Join(ctxt.IncludesDir(), words.fileName)
			logger.Info().Msgf("Writing word list for %s to %s", words.fileName, outPath)
			if err := p.writeIncludeWordListFile(outPath, words.functions, opts.FrequencyLimit, opts.AgeLimitDays, words.label, words.seeAlso); err != nil {
				return fmt.Errorf("writing %s word list: %w", words.fileName, err)
			}
		}
	}

	if doRule933161 {
		outPath := filepath.Join(ctxt.AssemblyDir(), Rule933161FileName)
		logger.Info().Msgf("Writing rule 933161 regex-assembly to %s", outPath)
		if err := p.writeAssemblyFile(outPath, englishWords, opts.FrequencyLimit, opts.AgeLimitDays); err != nil {
			return fmt.Errorf("writing 933161 assembly file: %w", err)
		}
	}

	return nil
}

// ExtractFunctions extracts PHP function names from ZEND_FUNCTION macros
// in the PHP source repository at phpRepoPath.
func (p *PhpDictionaryGen) ExtractFunctions(phpRepoPath string) ([]string, error) {
	seen := make(map[string]struct{})
	var functions []string

	err := filepath.WalkDir(phpRepoPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".c" && ext != ".h" {
			return nil
		}

		file, err := os.Open(path)
		if err != nil {
			logger.Warn().Err(err).Msgf("Failed to open file %s, skipping", path)
			return nil
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			// Skip macro definitions themselves, e.g.
			// `#define ZEND_FUNCTION(name) ZEND_NAMED_FUNCTION(zif_##name)` in
			// Zend/zend_API.h, which would otherwise match ZEND_FUNCTION(...)
			// and capture the bogus macro parameter "name" as a function.
			if strings.HasPrefix(strings.TrimSpace(line), "#define") {
				continue
			}
			// Skip lines with $ (template variables)
			if strings.Contains(line, "$") {
				continue
			}

			matches := zendFunctionRegex.FindAllStringSubmatch(line, -1)
			for _, match := range matches {
				if len(match) > 1 {
					fnName := strings.TrimSpace(match[1])
					if fnName != "" {
						if _, exists := seen[fnName]; !exists {
							seen[fnName] = struct{}{}
							functions = append(functions, fnName)
						}
					}
				}
			}
		}
		return scanner.Err()
	})

	if err != nil {
		return nil, err
	}

	slices.Sort(functions)
	return functions, nil
}

// classifyFunctions separates functions into English words (for 933161) and
// non-English words (for frequency-based classification into 933150/933151).
func (p *PhpDictionaryGen) classifyFunctions(functions []string, wn WordNet) (english, nonEnglish []string) {
	fpf := NewFpFinder()
	// filterContent retains words NOT in WordNet (non-English)
	nonEnglish = fpf.filterContent(functions, wn, map[string]struct{}{}, 1)

	// English words are those in functions but not in nonEnglish
	nonEnglishSet := make(map[string]struct{}, len(nonEnglish))
	for _, fn := range nonEnglish {
		nonEnglishSet[fn] = struct{}{}
	}
	for _, fn := range functions {
		if _, isNonEnglish := nonEnglishSet[fn]; !isNonEnglish {
			english = append(english, fn)
		}
	}

	return english, nonEnglish
}

// getOrUpdateFrequency returns the GitHub code frequency for the given function name,
// updating the cache if the entry is missing or stale.
func (p *PhpDictionaryGen) getOrUpdateFrequency(ctx context.Context, functionName string, cache map[string]frequencyEntry, searcher GitHubSearcher, ageLimit time.Duration, today string) (int, error) {
	if entry, ok := cache[functionName]; ok {
		age := time.Since(entry.updatedAt)
		if age <= ageLimit {
			logger.Debug().Msgf("Using cached frequency for %s: %d", functionName, entry.count)
			return entry.count, nil
		}
		logger.Debug().Msgf("Cache entry for %s is stale (age: %v), refreshing", functionName, age)
	}

	count, err := searcher.SearchCodeCount(ctx, functionName)
	var rlErr *rateLimitError
	if errors.As(err, &rlErr) && rlErr.hasRetryAfter {
		wait := rlErr.retryAfter
		if wait > maxRateLimitWait {
			wait = maxRateLimitWait
		}
		logger.Warn().Msgf("Waiting %v before retrying rate-limited lookup for %s", wait, functionName)
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-time.After(wait):
		}
		count, err = searcher.SearchCodeCount(ctx, functionName)
	}
	if err != nil {
		return 0, err
	}

	updatedAt, _ := time.Parse(frequencyListDateFormat, today)
	cache[functionName] = frequencyEntry{count: count, updatedAt: updatedAt}
	logger.Debug().Msgf("Fetched frequency for %s: %d", functionName, count)
	return count, nil
}

// loadFrequencyList loads the frequency cache from a file.
// Each line has the format: "function_name count date".
func (p *PhpDictionaryGen) loadFrequencyList(path string) (map[string]frequencyEntry, error) {
	cache := make(map[string]frequencyEntry)

	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return cache, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) != 3 {
			continue
		}
		count, err := strconv.Atoi(parts[1])
		if err != nil {
			continue
		}
		updatedAt, err := time.Parse(frequencyListDateFormat, parts[2])
		if err != nil {
			continue
		}
		cache[parts[0]] = frequencyEntry{count: count, updatedAt: updatedAt}
	}
	return cache, scanner.Err()
}

// saveFrequencyList saves the frequency cache to a file.
func (p *PhpDictionaryGen) saveFrequencyList(path string, cache map[string]frequencyEntry) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)

	// Collect and sort keys for deterministic output
	keys := make([]string, 0, len(cache))
	for k := range cache {
		keys = append(keys, k)
	}
	slices.Sort(keys)

	for _, fn := range keys {
		entry := cache[fn]
		if _, err := fmt.Fprintf(writer, "%s %d %s\n", fn, entry.count, entry.updatedAt.Format(frequencyListDateFormat)); err != nil {
			return err
		}
	}
	return writer.Flush()
}

// writeDataFile writes a list of function names to a .data file.
func (p *PhpDictionaryGen) writeDataFile(path string, functions []string, frequencyLimit, ageLimitDays int) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	if err := p.writeDataFileHeader(writer, frequencyLimit, ageLimitDays); err != nil {
		return err
	}

	for _, fn := range functions {
		if _, err := fmt.Fprintln(writer, fn); err != nil {
			return err
		}
	}
	return writer.Flush()
}

// writeAssemblyFile writes English PHP function names to a regex assembly file.
func (p *PhpDictionaryGen) writeAssemblyFile(path string, functions []string, frequencyLimit, ageLimitDays int) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	if err := p.writeAssemblyFileHeader(writer, frequencyLimit, ageLimitDays); err != nil {
		return err
	}

	for _, fn := range functions {
		if _, err := fmt.Fprintln(writer, fn); err != nil {
			return err
		}
	}
	return writer.Flush()
}

// writeIncludeWordListFile writes one alphabetical partition of the rare-function
// word list (rule 933151/933152/933153) to its regex-assembly include file.
func (p *PhpDictionaryGen) writeIncludeWordListFile(path string, functions []string, frequencyLimit, ageLimitDays int, label, seeAlso string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	if err := p.writeIncludeWordListFileHeader(writer, frequencyLimit, ageLimitDays, label, seeAlso); err != nil {
		return err
	}

	for _, fn := range functions {
		if _, err := fmt.Fprintln(writer, fn); err != nil {
			return err
		}
	}
	return writer.Flush()
}

func (p *PhpDictionaryGen) writeIncludeWordListFileHeader(w io.Writer, frequencyLimit, ageLimitDays int, label, seeAlso string) error {
	lines := []string{
		"##! Please refer to the documentation at",
		"##! https://coreruleset.org/docs/development/regex_assembly/.",
		"",
		fmt.Sprintf("##! File autogenerated by %s with: -a %d -F %d", generatorName, ageLimitDays, frequencyLimit),
		fmt.Sprintf("##! This file only includes words which start with %s. See %s.", label, seeAlso),
	}
	for _, line := range lines {
		if _, err := fmt.Fprintln(w, line); err != nil {
			return err
		}
	}
	return nil
}

func (p *PhpDictionaryGen) writeDataFileHeader(w io.Writer, frequencyLimit, ageLimitDays int) error {
	_, err := fmt.Fprintf(w, "##! File autogenerated by %s with: -a %d -F %d\n",
		generatorName, ageLimitDays, frequencyLimit)
	return err
}

func (p *PhpDictionaryGen) writeAssemblyFileHeader(w io.Writer, frequencyLimit, ageLimitDays int) error {
	lines := []string{
		"##! Please refer to the documentation at",
		"##! https://coreruleset.org/docs/development/regex_assembly/.",
		"",
		fmt.Sprintf("##! File autogenerated by %s with: -a %d -F %d", generatorName, ageLimitDays, frequencyLimit),
		"",
		"##!+ i",
		`##!^ \b`,
		`##!$ (?:\s|/\*.*\*/|#.*|//.*)*\(.*\)`,
		"",
	}
	for _, line := range lines {
		if _, err := fmt.Fprintln(w, line); err != nil {
			return err
		}
	}
	return nil
}

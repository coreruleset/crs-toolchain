// Copyright 2025 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"bufio"
	"context"
	"encoding/json"
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

	git "github.com/go-git/go-git/v5"
	"github.com/coreruleset/wnram"

	crsctx "github.com/coreruleset/crs-toolchain/v2/context"
	"github.com/coreruleset/crs-toolchain/v2/utils"
)

const (
	phpRepoURL              = "https://github.com/php/php-src"
	DefaultFrequencyLimit   = 90000
	DefaultAgeLimitDays     = 30
	Rule933150FileName      = "php-function-names-933150.data"
	Rule933151FileName      = "php-function-names-933151.data"
	Rule933161FileName      = "933161.ra"
	gitHubSearchAPIFormat   = "https://api.github.com/search/code?q=%s+language:php&type=Code&per_page=1"
	gitHubAPIVersion        = "2022-11-28"
	frequencyListDateFormat = "2006-01-02"
)

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
	// Functions with fewer occurrences will be placed in rule 933151.
	FrequencyLimit int
	// AgeLimitDays is the number of days before a frequency cache entry is considered stale.
	AgeLimitDays int
	// FrequencyListPath is the path to the frequency cache file.
	// If empty, no caching is used.
	FrequencyListPath string
	// Rules is a list of rule IDs to generate (e.g. ["933150", "933151", "933161"]).
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
		// Try to honour the Retry-After header so the caller knows when to retry.
		if retryAfter := resp.Header.Get("Retry-After"); retryAfter != "" {
			if secs, err := strconv.Atoi(retryAfter); err == nil {
				logger.Warn().Msgf("GitHub API rate limit hit for %s; retry after %d seconds", functionName, secs)
			}
		} else if resetHeader := resp.Header.Get("X-RateLimit-Reset"); resetHeader != "" {
			if resetUnix, err := strconv.ParseInt(resetHeader, 10, 64); err == nil {
				resetTime := time.Unix(resetUnix, 0)
				logger.Warn().Msgf("GitHub API rate limit hit for %s; resets at %v", functionName, resetTime)
			}
		} else {
			logger.Warn().Msgf("GitHub API rate limit hit for %s (status %d)", functionName, resp.StatusCode)
		}
		return 0, fmt.Errorf("GitHub API rate limit exceeded for %s (status %d)", functionName, resp.StatusCode)
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
		rules = []string{"933150", "933151", "933161"}
	}

	// Determine which rules to generate
	doRule933150 := slices.Contains(rules, "933150")
	doRule933151 := slices.Contains(rules, "933151")
	doRule933161 := slices.Contains(rules, "933161")

	// Initialize WordNet if not provided; it is needed for all rule combinations
	// because classifyFunctions (which separates English/non-English names) is
	// called whenever any rule is being generated.
	if wn == nil && (doRule933161 || doRule933150 || doRule933151) {
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
		_, err = git.PlainClone(tmpDir, false, &git.CloneOptions{
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

	if doRule933150 || doRule933151 {
		today := time.Now().Format(frequencyListDateFormat)
		ageLimitDuration := time.Duration(opts.AgeLimitDays) * 24 * time.Hour

		for _, fn := range nonEnglishWords {
			count, err := p.getOrUpdateFrequency(ctx, fn, frequencyCache, searcher, ageLimitDuration, today)
			if err != nil {
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

	if doRule933151 {
		outPath := filepath.Join(ctxt.RulesDir(), Rule933151FileName)
		logger.Info().Msgf("Writing rule 933151 data to %s", outPath)
		if err := p.writeDataFile(outPath, rareFunctions, opts.FrequencyLimit, opts.AgeLimitDays); err != nil {
			return fmt.Errorf("writing 933151 data file: %w", err)
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

func (p *PhpDictionaryGen) writeDataFileHeader(w io.Writer, frequencyLimit, ageLimitDays int) error {
	_, err := fmt.Fprintf(w, "##! File autogenerated by util/php-dictionary-gen with: -a %d -F %d\n",
		ageLimitDays, frequencyLimit)
	return err
}

func (p *PhpDictionaryGen) writeAssemblyFileHeader(w io.Writer, frequencyLimit, ageLimitDays int) error {
	lines := []string{
		"##! Please refer to the documentation at",
		"##! https://coreruleset.org/docs/development/regex_assembly/.",
		"",
		fmt.Sprintf("##! File autogenerated by util/php-dictionary-gen with: -a %d -F %d", ageLimitDays, frequencyLimit),
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

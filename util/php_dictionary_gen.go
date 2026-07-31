// Copyright 2025 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"bufio"
	"context"
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

	"github.com/cli/go-gh/v2/pkg/api"
	"github.com/coreruleset/wnram"
	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/storage/memory"

	"github.com/coreruleset/crs-toolchain/v2/configuration"
	crsctx "github.com/coreruleset/crs-toolchain/v2/context"
	"github.com/coreruleset/crs-toolchain/v2/utils"
)

const (
	frequencyListDateFormat = "2006-01-02"
	generatorName           = "crs-toolchain generate php-function-names"
	gitHubAPIVersion        = "2022-11-28"

	// staleFrequencyHardLimitMultiplier bounds how far past the configured
	// age limit a cached frequency entry may still be used as a fallback
	// when refreshing it fails. Beyond ageLimit * staleFrequencyHardLimitMultiplier,
	// getOrUpdateFrequency gives up and returns an error instead of trusting
	// a value that has gotten too old.
	staleFrequencyHardLimitMultiplier = 3
)

// These re-export the configuration package's PhpDictionaryGen defaults for
// callers (such as cobra flag registration and tests) that only need the
// code-level fallback, not the full toolchain.yaml-aware value.
const (
	DefaultFrequencyLimit       = configuration.DefaultFrequencyLimit
	DefaultAgeLimitDays         = configuration.DefaultAgeLimitDays
	DefaultPhpMajorVersionCount = configuration.DefaultPhpMajorVersionCount
	DefaultRule933150FileName   = configuration.DefaultRule933150FileName
	DefaultRule933151FileName   = configuration.DefaultRule933151FileName
	DefaultRule933152FileName   = configuration.DefaultRule933152FileName
	DefaultRule933153FileName   = configuration.DefaultRule933153FileName
	DefaultRule933161FileName   = configuration.DefaultRule933161FileName
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

// errFrequencyUnavailable indicates no frequency value could be obtained for
// functionName and there was no cached entry to fall back to.
type errFrequencyUnavailable struct {
	functionName string
	cause        error
}

func (e *errFrequencyUnavailable) Error() string {
	return fmt.Sprintf("no frequency available for %s: %v", e.functionName, e.cause)
}

func (e *errFrequencyUnavailable) Unwrap() error { return e.cause }

// errFrequencyRenewalExpired indicates a cached frequency entry for
// functionName exists but is older than staleFrequencyHardLimitMultiplier *
// ageLimit, and the attempt to refresh it failed, so the stale value can no
// longer be trusted.
type errFrequencyRenewalExpired struct {
	functionName string
	age          time.Duration
	cause        error
}

func (e *errFrequencyRenewalExpired) Error() string {
	return fmt.Sprintf("frequency for %s is %v old and renewal failed: %v", e.functionName, e.age, e.cause)
}

func (e *errFrequencyRenewalExpired) Unwrap() error { return e.cause }

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

// buildRareWordRanges describes the three alphabetical partitions using the
// (possibly configured) file names from opts, so the "see also" cross
// references always point at the actual output file names.
func buildRareWordRanges(opts PhpDictionaryGenOptions) []rareWordRange {
	return []rareWordRange{
		{
			fileName: opts.Rule933151FileName,
			label:    "a-j",
			seeAlso:  fmt.Sprintf("%s and %s", opts.Rule933152FileName, opts.Rule933153FileName),
			from:     'a', to: 'j',
		},
		{
			fileName: opts.Rule933152FileName,
			label:    "k-q",
			seeAlso:  fmt.Sprintf("%s and %s", opts.Rule933151FileName, opts.Rule933153FileName),
			from:     'k', to: 'q',
		},
		{
			fileName: opts.Rule933153FileName,
			label:    "r-z",
			seeAlso:  fmt.Sprintf("%s and %s", opts.Rule933151FileName, opts.Rule933152FileName),
			from:     'r', to: 'z',
		},
	}
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

// phpReleaseBranchPattern matches php-src's release branch naming convention:
// the bare, actively-developed minor branch ("PHP-8.3") and the frozen
// per-patch branches php-src also keeps around ("PHP-8.3.31"). Some old
// minors (e.g. PHP-4.2) only exist as patch branches, with no bare branch at
// all, so both forms must be matched to discover every minor version.
var phpReleaseBranchPattern = regexp.MustCompile(`^PHP-(\d+)\.(\d+)(?:\.(\d+))?$`)

// GitHubSearcher defines the interface for checking PHP function frequency on GitHub.
type GitHubSearcher interface {
	SearchCodeCount(ctx context.Context, functionName string) (int, error)
}

// PhpDictionaryGenOptions contains options for PHP dictionary generation.
type PhpDictionaryGenOptions struct {
	// PhpRepoPath is the path to a local PHP source repository.
	// If empty, the PHP repository will be cloned from GitHub, and, in
	// addition to its default branch, release branches from
	// PhpMajorVersionCount of its most recent major versions will also be
	// cloned and scanned.
	PhpRepoPath string
	// PhpRepoURL is the repository to clone when PhpRepoPath is empty.
	PhpRepoURL string
	// PhpMajorVersionCount is the number of most recent PHP major versions
	// (beyond the default branch) to also extract function names from. Only
	// applies when PhpRepoPath is empty; see selectReleaseBranches for how
	// branches are chosen within each major version.
	PhpMajorVersionCount int
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
	// Rule933150FileName..Rule933161FileName are the output file names used for each generated rule.
	Rule933150FileName string
	Rule933151FileName string
	Rule933152FileName string
	Rule933153FileName string
	Rule933161FileName string
	// MaxRateLimitWait caps how long getOrUpdateFrequency will sleep before
	// retrying a rate-limited request, in case the server-reported wait time
	// (e.g. X-RateLimit-Reset far in the future) is unexpectedly large.
	MaxRateLimitWait time.Duration
}

// applyDefaults fills any zero-valued fields in opts with the configuration
// package's defaults, so Generate can be called directly (e.g. from tests)
// without requiring every option to be set.
func applyDefaults(opts PhpDictionaryGenOptions) PhpDictionaryGenOptions {
	if opts.PhpRepoURL == "" {
		opts.PhpRepoURL = configuration.DefaultPhpRepoURL
	}
	if opts.PhpMajorVersionCount == 0 {
		opts.PhpMajorVersionCount = configuration.DefaultPhpMajorVersionCount
	}
	if opts.FrequencyLimit <= 0 {
		opts.FrequencyLimit = configuration.DefaultFrequencyLimit
	}
	if opts.AgeLimitDays <= 0 {
		opts.AgeLimitDays = configuration.DefaultAgeLimitDays
	}
	if opts.Rule933150FileName == "" {
		opts.Rule933150FileName = configuration.DefaultRule933150FileName
	}
	if opts.Rule933151FileName == "" {
		opts.Rule933151FileName = configuration.DefaultRule933151FileName
	}
	if opts.Rule933152FileName == "" {
		opts.Rule933152FileName = configuration.DefaultRule933152FileName
	}
	if opts.Rule933153FileName == "" {
		opts.Rule933153FileName = configuration.DefaultRule933153FileName
	}
	if opts.Rule933161FileName == "" {
		opts.Rule933161FileName = configuration.DefaultRule933161FileName
	}
	if opts.MaxRateLimitWait <= 0 {
		opts.MaxRateLimitWait = time.Duration(configuration.DefaultMaxRateLimitWaitSecs) * time.Second
	}
	return opts
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
	client *api.RESTClient
}

// NewGitHubSearchClient creates a GitHubSearcher backed by go-gh's REST
// client. If token is empty, go-gh falls back to its usual token resolution
// (GH_TOKEN/GITHUB_TOKEN environment variables or the gh CLI's own config).
func NewGitHubSearchClient(token string) (*gitHubSearchClient, error) {
	client, err := api.NewRESTClient(api.ClientOptions{
		AuthToken: token,
		Headers: map[string]string{
			"Accept":               "application/vnd.github+json",
			"X-GitHub-Api-Version": gitHubAPIVersion,
		},
		Timeout: 30 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("creating GitHub REST client: %w", err)
	}
	return &gitHubSearchClient{client: client}, nil
}

// SearchCodeCount returns the number of GitHub code search results for the given PHP function name.
func (c *gitHubSearchClient) SearchCodeCount(ctx context.Context, functionName string) (int, error) {
	escapedName := url.QueryEscape(functionName)
	path := fmt.Sprintf("search/code?q=%s+language:php&type=Code&per_page=1", escapedName)

	var result struct {
		TotalCount int `json:"total_count"`
	}
	if err := c.client.DoWithContext(ctx, http.MethodGet, path, nil, &result); err != nil {
		var httpErr *api.HTTPError
		if errors.As(err, &httpErr) && (httpErr.StatusCode == http.StatusForbidden || httpErr.StatusCode == http.StatusTooManyRequests) {
			return 0, newRateLimitError(functionName, httpErr)
		}
		return 0, fmt.Errorf("fetching frequency for %s: %w", functionName, err)
	}

	return result.TotalCount, nil
}

// newRateLimitError builds a rateLimitError from a rate-limited HTTP
// response, trying to honour the Retry-After or X-RateLimit-Reset headers so
// the caller knows when to retry.
func newRateLimitError(functionName string, httpErr *api.HTTPError) *rateLimitError {
	rlErr := &rateLimitError{functionName: functionName, statusCode: httpErr.StatusCode}

	if retryAfter := httpErr.Headers.Get("Retry-After"); retryAfter != "" {
		if secs, err := strconv.Atoi(retryAfter); err == nil {
			rlErr.retryAfter = time.Duration(secs) * time.Second
			rlErr.hasRetryAfter = true
			logger.Warn().Msgf("GitHub API rate limit hit for %s; retry after %d seconds", functionName, secs)
		}
	} else if resetHeader := httpErr.Headers.Get("X-RateLimit-Reset"); resetHeader != "" {
		if resetUnix, err := strconv.ParseInt(resetHeader, 10, 64); err == nil {
			resetTime := time.Unix(resetUnix, 0)
			if wait := time.Until(resetTime); wait > 0 {
				rlErr.retryAfter = wait
				rlErr.hasRetryAfter = true
			}
			logger.Warn().Msgf("GitHub API rate limit hit for %s; resets at %v", functionName, resetTime)
		}
	} else {
		logger.Warn().Msgf("GitHub API rate limit hit for %s (status %d)", functionName, httpErr.StatusCode)
	}

	return rlErr
}

// Generate runs the PHP dictionary generation process.
// It extracts PHP function names from the PHP source, classifies them using
// WordNet, checks their GitHub frequency, and writes the output files to the
// appropriate CRS directories.
// If wn is nil, a WordNet instance is created automatically (downloading the
// dictionary if needed).
func (p *PhpDictionaryGen) Generate(ctx context.Context, ctxt *crsctx.Context, opts PhpDictionaryGenOptions, wn WordNet, searcher GitHubSearcher) error {
	opts = applyDefaults(opts)

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

	functions, err := p.extractAllFunctions(ctx, opts)
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
	var frequentFunctions, rareFunctions []string
	if doRule933150 || doRuleRare {
		frequentFunctions, rareFunctions, err = p.categorizeByFrequency(ctx, nonEnglishWords, frequencyCache, searcher, opts)
		if err != nil {
			return err
		}
	}

	// Sort all output
	slices.Sort(englishWords)
	slices.Sort(frequentFunctions)
	slices.Sort(rareFunctions)

	// Write output files
	if doRule933150 {
		outPath := filepath.Join(ctxt.RulesDir(), opts.Rule933150FileName)
		logger.Info().Msgf("Writing rule 933150 data to %s", outPath)
		if err := p.writeDataFile(outPath, frequentFunctions, opts.FrequencyLimit, opts.AgeLimitDays); err != nil {
			return fmt.Errorf("writing 933150 data file: %w", err)
		}
	}

	if doRuleRare {
		requested := map[string]bool{
			opts.Rule933151FileName: doRule933151,
			opts.Rule933152FileName: doRule933152,
			opts.Rule933153FileName: doRule933153,
		}
		for _, words := range partitionRareFunctionsAlphabetically(rareFunctions, buildRareWordRanges(opts)) {
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
		outPath := filepath.Join(ctxt.AssemblyDir(), opts.Rule933161FileName)
		logger.Info().Msgf("Writing rule 933161 regex-assembly to %s", outPath)
		if err := p.writeAssemblyFile(outPath, englishWords, opts.FrequencyLimit, opts.AgeLimitDays); err != nil {
			return fmt.Errorf("writing 933161 assembly file: %w", err)
		}
	}

	return nil
}

// extractAllFunctions obtains the PHP function names to classify.
// If opts.PhpRepoPath is set, it scans that local checkout as-is (release
// branches are not considered, since the tool doesn't own that directory).
// Otherwise, it clones opts.PhpRepoURL's default branch plus, when
// opts.PhpMajorVersionCount > 0, release branches from that many of its most
// recent major versions, merging and deduplicating function names across all
// of them. All temporary clones are cleaned up before returning.
func (p *PhpDictionaryGen) extractAllFunctions(ctx context.Context, opts PhpDictionaryGenOptions) ([]string, error) {
	if opts.PhpRepoPath != "" {
		logger.Info().Msgf("Using local PHP repository at %s; not checking release branches", opts.PhpRepoPath)
		return p.ExtractFunctions(opts.PhpRepoPath)
	}

	var cleanupDirs []string
	defer func() {
		for _, dir := range cleanupDirs {
			if err := os.RemoveAll(dir); err != nil {
				logger.Warn().Err(err).Msgf("Failed to clean up temporary PHP repo at %s", dir)
			}
		}
	}()

	logger.Info().Msg("Extracting PHP function names")
	functions, mainDir, err := p.cloneAndExtract(ctx, opts.PhpRepoURL, "")
	if mainDir != "" {
		cleanupDirs = append(cleanupDirs, mainDir)
	}
	if err != nil {
		return nil, err
	}

	releaseBranches, err := listReleaseBranchesToScan(ctx, opts.PhpRepoURL, opts.PhpMajorVersionCount)
	if err != nil {
		return nil, fmt.Errorf("listing PHP release branches: %w", err)
	}
	if len(releaseBranches) > 0 {
		logger.Info().Msgf("Also extracting functions from release branches: %v", releaseBranches)
	}

	for _, branch := range releaseBranches {
		branchFunctions, branchDir, err := p.cloneAndExtract(ctx, opts.PhpRepoURL, branch)
		if branchDir != "" {
			cleanupDirs = append(cleanupDirs, branchDir)
		}
		if err != nil {
			return nil, err
		}
		functions = mergeUniqueSorted(functions, branchFunctions)
	}

	return functions, nil
}

// cloneAndExtract shallow-clones repoURL at branch (or its default branch, if
// branch is empty) into a new temporary directory and extracts PHP function
// names from it. The temporary directory is always returned, even on error,
// so the caller can clean it up.
func (p *PhpDictionaryGen) cloneAndExtract(ctx context.Context, repoURL, branch string) ([]string, string, error) {
	tmpDir, err := os.MkdirTemp("", "php-src-")
	if err != nil {
		return nil, "", fmt.Errorf("creating temp directory for PHP repo: %w", err)
	}

	cloneOpts := &git.CloneOptions{URL: repoURL, Depth: 1}
	label := "default branch"
	if branch != "" {
		cloneOpts.ReferenceName = plumbing.NewBranchReferenceName(branch)
		cloneOpts.SingleBranch = true
		label = branch
	}

	logger.Info().Msgf("Cloning PHP repository %s (%s)", repoURL, label)
	if _, err := git.PlainCloneContext(ctx, tmpDir, false, cloneOpts); err != nil {
		return nil, tmpDir, fmt.Errorf("cloning %s: %w", label, err)
	}

	functions, err := p.ExtractFunctions(tmpDir)
	if err != nil {
		return nil, tmpDir, fmt.Errorf("extracting functions from %s: %w", label, err)
	}
	return functions, tmpDir, nil
}

// phpRelease is a parsed PHP release branch name. Patch is -1 for a bare
// "PHP-X.Y" branch (which has no patch component of its own).
type phpRelease struct {
	name                string
	major, minor, patch int
}

// listReleaseBranchesToScan discovers repoURL's PHP-X.Y release branches
// (without cloning the repository) and returns the ones selectReleaseBranches
// picks for majorVersionCount.
func listReleaseBranchesToScan(ctx context.Context, repoURL string, majorVersionCount int) ([]string, error) {
	if majorVersionCount <= 0 {
		return nil, nil
	}

	remote := git.NewRemote(memory.NewStorage(), &config.RemoteConfig{
		Name: "origin",
		URLs: []string{repoURL},
	})
	refs, err := remote.ListContext(ctx, &git.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing remote branches for %s: %w", repoURL, err)
	}

	var releases []phpRelease
	for _, ref := range refs {
		if !ref.Name().IsBranch() {
			continue
		}
		match := phpReleaseBranchPattern.FindStringSubmatch(ref.Name().Short())
		if match == nil {
			continue
		}
		major, _ := strconv.Atoi(match[1])
		minor, _ := strconv.Atoi(match[2])
		patch := -1
		if match[3] != "" {
			patch, _ = strconv.Atoi(match[3])
		}
		releases = append(releases, phpRelease{name: ref.Name().Short(), major: major, minor: minor, patch: patch})
	}

	return selectReleaseBranches(releases, majorVersionCount), nil
}

// selectReleaseBranches picks which PHP release branches to scan for function
// names out of all known releases: the majorVersionCount most recent major
// versions, and for each of those, only its oldest and newest minor version
// (deduplicated when a major has just one minor).
//
// Minor versions within a single PHP major are too numerous to all clone
// cheaply, and a function's presence rarely changes across minors within the
// same major, so scanning just the oldest and newest minor is a deliberate
// performance/completeness trade-off: a function added and later removed
// within a single major's intermediate minors (skipping its oldest and
// newest) could be missed, but that's an unlikely, narrow gap.
func selectReleaseBranches(releases []phpRelease, majorVersionCount int) []string {
	if majorVersionCount <= 0 {
		return nil
	}

	byMajor := make(map[int][]phpRelease)
	for _, r := range releases {
		byMajor[r.major] = append(byMajor[r.major], r)
	}

	majors := make([]int, 0, len(byMajor))
	for major := range byMajor {
		majors = append(majors, major)
	}
	slices.SortFunc(majors, func(a, b int) int { return b - a })
	if len(majors) > majorVersionCount {
		majors = majors[:majorVersionCount]
	}

	var branches []string
	for _, major := range majors {
		group := byMajor[major]
		minMinor, maxMinor := group[0].minor, group[0].minor
		for _, r := range group {
			minMinor = min(minMinor, r.minor)
			maxMinor = max(maxMinor, r.minor)
		}
		oldest := representativeBranch(group, minMinor)
		branches = append(branches, oldest)
		if maxMinor != minMinor {
			branches = append(branches, representativeBranch(group, maxMinor))
		}
	}
	return branches
}

// representativeBranch picks the branch that best represents minor within
// group. Some minors (e.g. PHP-4.2) only exist as patch branches, with no
// bare branch at all, so minors are discovered from both forms; the bare
// "PHP-X.Y" branch is preferred when present, since it's the mutable tip and
// therefore the freshest code for that line, otherwise the highest-numbered
// patch branch is used.
func representativeBranch(group []phpRelease, minor int) string {
	var best phpRelease
	found := false
	for _, r := range group {
		if r.minor != minor {
			continue
		}
		if r.patch == -1 {
			return r.name
		}
		if !found || r.patch > best.patch {
			best, found = r, true
		}
	}
	return best.name
}

// mergeUniqueSorted merges function name lists gathered from multiple
// ZEND_FUNCTION extraction passes (e.g. main plus several PHP release
// branches) into a single deduplicated, sorted list.
func mergeUniqueSorted(lists ...[]string) []string {
	seen := make(map[string]struct{})
	var merged []string
	for _, list := range lists {
		for _, fn := range list {
			if _, ok := seen[fn]; ok {
				continue
			}
			seen[fn] = struct{}{}
			merged = append(merged, fn)
		}
	}
	slices.Sort(merged)
	return merged
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

// frequencyLookupParams bundles the tunable parameters for a single
// getOrUpdateFrequency call.
type frequencyLookupParams struct {
	ageLimit         time.Duration
	today            string
	maxRateLimitWait time.Duration
}

// categorizeByFrequency splits nonEnglishWords into frequent (GitHub
// occurrence count above opts.FrequencyLimit) and rare functions, consulting
// and updating frequencyCache along the way, and persists the cache if
// opts.FrequencyListPath is set.
func (p *PhpDictionaryGen) categorizeByFrequency(ctx context.Context, nonEnglishWords []string, frequencyCache map[string]frequencyEntry, searcher GitHubSearcher, opts PhpDictionaryGenOptions) (frequent, rare []string, err error) {
	lookupParams := frequencyLookupParams{
		ageLimit:         time.Duration(opts.AgeLimitDays) * 24 * time.Hour,
		today:            time.Now().Format(frequencyListDateFormat),
		maxRateLimitWait: opts.MaxRateLimitWait,
	}

	for _, fn := range nonEnglishWords {
		count, err := p.getOrUpdateFrequency(ctx, fn, frequencyCache, searcher, lookupParams)
		if err != nil {
			return nil, nil, fmt.Errorf("getting frequency for %s: %w", fn, err)
		}

		if count > opts.FrequencyLimit {
			frequent = append(frequent, fn)
		} else {
			rare = append(rare, fn)
		}
	}

	if opts.FrequencyListPath != "" {
		if err := p.saveFrequencyList(opts.FrequencyListPath, frequencyCache); err != nil {
			return nil, nil, fmt.Errorf("saving frequency list: %w", err)
		}
	}

	return frequent, rare, nil
}

// getOrUpdateFrequency returns the GitHub code frequency for the given
// function name, updating cache if the entry is missing or stale.
//
// If refreshing a stale entry fails, the stale value is still returned as
// long as its age is within staleFrequencyHardLimitMultiplier * ageLimit
// (errFrequencyRenewalExpired otherwise); if there was no cached entry at
// all, errFrequencyUnavailable is returned. Both cause the caller to fail
// rather than silently guessing a frequency.
func (p *PhpDictionaryGen) getOrUpdateFrequency(ctx context.Context, functionName string, cache map[string]frequencyEntry, searcher GitHubSearcher, params frequencyLookupParams) (int, error) {
	entry, hasEntry := cache[functionName]
	if hasEntry {
		age := time.Since(entry.updatedAt)
		if age <= params.ageLimit {
			logger.Debug().Msgf("Using cached frequency for %s: %d", functionName, entry.count)
			return entry.count, nil
		}
		logger.Debug().Msgf("Cache entry for %s is stale (age: %v), refreshing", functionName, age)
	}

	count, err := searcher.SearchCodeCount(ctx, functionName)
	var rlErr *rateLimitError
	if errors.As(err, &rlErr) && rlErr.hasRetryAfter {
		wait := min(rlErr.retryAfter, params.maxRateLimitWait)
		logger.Warn().Msgf("Waiting %v before retrying rate-limited lookup for %s", wait, functionName)
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-time.After(wait):
		}
		count, err = searcher.SearchCodeCount(ctx, functionName)
	}

	if err == nil {
		updatedAt, _ := time.Parse(frequencyListDateFormat, params.today)
		cache[functionName] = frequencyEntry{count: count, updatedAt: updatedAt}
		logger.Debug().Msgf("Fetched frequency for %s: %d", functionName, count)
		return count, nil
	}

	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return 0, err
	}

	if !hasEntry {
		return 0, &errFrequencyUnavailable{functionName: functionName, cause: err}
	}

	age := time.Since(entry.updatedAt)
	if hardLimit := params.ageLimit * staleFrequencyHardLimitMultiplier; age > hardLimit {
		return 0, &errFrequencyRenewalExpired{functionName: functionName, age: age, cause: err}
	}

	logger.Warn().Err(err).Msgf("Failed to refresh frequency for %s; using stale cached value %d (age %v)", functionName, entry.count, age)
	return entry.count, nil
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

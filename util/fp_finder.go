// Copyright 2025 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/coreruleset/wnram"

	"github.com/coreruleset/crs-toolchain/v2/utils"
)

type FpFinderError struct{}

const wordNetOwner = "globalwordnet"
const wordNetRepo = "english-wordnet"
const minSize = 3

type WordNet interface {
	Lookup(criteria wnram.Criteria) ([]wnram.Lookup, error)
}

func (t *FpFinderError) Error() string {
	return "FpFinder error"
}

type FpFinder struct{}

func NewFpFinder() *FpFinder {
	return &FpFinder{}
}

// dictionaryCacheKey builds the cache directory name for a downloaded
// WordNet release. It combines the release tag with the matched asset name
// so that a release gaining, losing, or renaming assets without a tag change
// results in a new cache entry rather than silently reusing a stale,
// differently-formatted dictionary cached under the tag alone.
func dictionaryCacheKey(tag, assetName string) string {
	return fmt.Sprintf("%s-%s", tag, assetName)
}

// getDictionaryPath ensures a valid WordNet dictionary is cached locally and
// returns its path, fetching the latest English WordNet release from GitHub
// first if needed.
func getDictionaryPath() (string, error) {
	// Fetch the latest English WordNet release from GitHub
	tag, assetName, downloadURL, err := utils.GetLatestGitHubRelease(wordNetOwner, wordNetRepo, func(name string) bool {
		return strings.HasSuffix(name, ".zip") &&
			strings.HasPrefix(name, "english-wordnet-") &&
			!strings.Contains(name, "-plus")
	})
	if err != nil {
		return "", fmt.Errorf("getting latest English WordNet release: %w", err)
	}

	// Get the dictionary path in ~/.crs-toolchain, named after the release tag and
	// asset. The asset name is included because a release can gain, lose, or
	// rename assets without its tag changing; keying the cache on the tag alone
	// would silently keep serving a stale, differently-formatted dictionary in
	// that case.
	dictionaryPath, err := utils.GetCacheFilePath(dictionaryCacheKey(tag, assetName))
	if err != nil {
		return "", fmt.Errorf("getting dictionary path: %w", err)
	}

	// Ensure a valid dictionary is available at dictionaryPath, downloading it
	// if the cached copy is missing or unusable.
	if err := ensureDictionary(dictionaryPath, downloadURL, tag, assetName); err != nil {
		return "", fmt.Errorf("preparing dictionary: %w", err)
	}

	return dictionaryPath, nil
}

func (t *FpFinder) FpFinder(inputFilePath string, extendedDictionaryFilePath string) error {
	dictionaryPath, err := getDictionaryPath()
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to prepare dictionary")
	}

	var extendedDict map[string]struct{}
	if extendedDictionaryFilePath != "" {
		extendedDict, err = t.loadDictionary(extendedDictionaryFilePath, 0)
		if err != nil {
			logger.Fatal().Err(err).Msg("Failed to load extended dictionary")
		}
	}

	// Load input file into memory
	inputFile, err := t.loadInput(inputFilePath)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to load input file")
	}

	wn, err := wnram.New(dictionaryPath)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to load WordNet")
	}

	// Process words from inputfile, sort the output and remove duplicates
	filteredWords := t.processWords(inputFile, wn, extendedDict, minSize)

	for _, str := range filteredWords {
		fmt.Println(str)
	}

	return nil
}

// ensureDictionary makes sure a valid WordNet dictionary exists at
// dictionaryPath. A cached copy is reused only when it passes validation;
// otherwise the dictionary is downloaded from downloadURL into a temporary
// directory, validated there, and only then atomically renamed into place.
// This guarantees an interrupted or corrupt download never leaves a broken
// dictionary behind that a later run would mistake for a valid cache entry.
func ensureDictionary(dictionaryPath, downloadURL, tag, assetName string) error {
	switch _, err := os.Stat(dictionaryPath); {
	case err == nil:
		if validateDictionary(dictionaryPath) == nil {
			logger.Debug().Msgf("Dictionary for %s (%s) found, skipping download.", tag, assetName)
			return nil
		}
		// A cached copy exists but is unusable; discard it before re-downloading.
		logger.Warn().Msgf("Cached dictionary for %s (%s) is invalid, re-downloading.", tag, assetName)
		if err := os.RemoveAll(dictionaryPath); err != nil {
			return fmt.Errorf("removing invalid cached dictionary: %w", err)
		}
	case os.IsNotExist(err):
		// No cached copy; fall through to download.
	default:
		return fmt.Errorf("checking dictionary cache: %w", err)
	}

	logger.Debug().Msgf("Downloading English WordNet %s (%s) from %s to %s", tag, assetName, downloadURL, dictionaryPath)

	tmpParent, err := os.MkdirTemp(filepath.Dir(dictionaryPath), filepath.Base(dictionaryPath)+".tmp-*")
	if err != nil {
		return fmt.Errorf("creating temporary download directory: %w", err)
	}
	// Always clean up the temporary directory. On success it has already been
	// renamed away, so RemoveAll is a harmless no-op.
	defer os.RemoveAll(tmpParent)

	tmpDictionary := filepath.Join(tmpParent, "dictionary")
	if err := utils.DownloadFile(tmpDictionary, downloadURL); err != nil {
		return fmt.Errorf("downloading dictionary: %w", err)
	}
	if err := validateDictionary(tmpDictionary); err != nil {
		return fmt.Errorf("validating downloaded dictionary: %w", err)
	}
	if err := os.Rename(tmpDictionary, dictionaryPath); err != nil {
		return fmt.Errorf("installing downloaded dictionary: %w", err)
	}

	logger.Debug().Msg("Download complete.")
	return nil
}

// errDictionaryHasEntries is a sentinel used to stop iterating as soon as the
// dictionary is shown to contain at least one entry.
var errDictionaryHasEntries = errors.New("dictionary has entries")

// validateDictionary reports whether the WordNet dictionary at path can be
// loaded and actually contains entries. wnram.New succeeds even on an empty or
// partially-extracted directory (it simply finds no data files to read), so a
// non-empty check is required to reject a broken download.
func validateDictionary(path string) error {
	wn, err := wnram.New(path)
	if err != nil {
		return err
	}

	found := false
	err = wn.Iterate(nil, func(wnram.Lookup) error {
		found = true
		return errDictionaryHasEntries
	})
	if err != nil && !errors.Is(err, errDictionaryHasEntries) {
		return err
	}
	if !found {
		return fmt.Errorf("dictionary at %s contains no entries", path)
	}

	return nil
}

func (t *FpFinder) loadDictionary(path string, minWordLength int) (map[string]struct{}, error) {
	lines, err := t.loadInput(path)
	if err != nil {
		return nil, err
	}

	content := make(map[string]struct{})
	for _, word := range lines {
		if len(word) >= minWordLength {
			content[word] = struct{}{}
		}
	}

	return content, nil
}

func (t *FpFinder) loadInput(path string) ([]string, error) {
	if path == "-" {
		return t.loadInputFromStdIn()
	} else {
		return t.loadInputFromFile(path)
	}
}

func (t *FpFinder) loadInputFromStdIn() ([]string, error) {
	logger.Trace().Msg("Reading from stdin")
	words, err := t.wordsFromInput(os.Stdin)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to read from stdin")
	}
	return words, nil
}

func (t *FpFinder) loadInputFromFile(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	defer file.Close()
	return t.wordsFromInput(file)
}

func (t *FpFinder) wordsFromInput(reader io.Reader) ([]string, error) {
	var content []string

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		content = append(content, word)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return content, nil
}

func (t *FpFinder) processWords(inputFile []string, wn WordNet, extendedDict map[string]struct{}, minSize int) []string {
	// Filter words not in the dictionary
	filteredWords := t.filterContent(inputFile, wn, extendedDict, minSize)

	// Sort words alphabetically (case-insensitive)
	slices.SortFunc(filteredWords, func(a, b string) int {
		return strings.Compare(strings.ToLower(a), strings.ToLower(b))
	})

	// Remove adjacent duplicate words from the sorted list
	filteredWords = slices.Compact(filteredWords)

	return filteredWords
}

func (t *FpFinder) filterContent(inputFile []string, wn WordNet, extendedDict map[string]struct{}, minSize int) []string {
	var commentPattern = regexp.MustCompile(`^\s*#`)
	var filteredWords []string
	for _, word := range inputFile {
		if commentPattern.MatchString(word) {
			continue
		}

		if word == "" || len(word) < minSize {
			continue
		}
		// Check if the word exists in WordNet
		found, err := wn.Lookup(wnram.Criteria{Matching: word})
		if err != nil {
			logger.Fatal().Err(err).Msg("Failed to lookup word in WordNet")
		}

		// If the word is not in the dictionary and extended dictionary, add it to the filtered list
		if len(found) == 0 {
			if _, found := extendedDict[word]; !found {
				filteredWords = append(filteredWords, word)
			} else {
				logger.Debug().Msgf("Word '%s' found in extended dictionary", word)
			}
		} else {
			logger.Debug().Msgf("Word '%s' found in WordNet", word)
		}
	}

	return filteredWords
}

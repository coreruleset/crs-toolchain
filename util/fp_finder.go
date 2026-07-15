// Copyright 2025 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"bufio"
	"fmt"
	"io"
	"os"
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

func (t *FpFinder) FpFinder(inputFilePath string, extendedDictionaryFilePath string, englishDictionaryCommitRef string) error {
	// Fetch the latest English WordNet release from GitHub
	tag, assetName, downloadURL, err := utils.GetLatestGitHubRelease(wordNetOwner, wordNetRepo, func(name string) bool {
		return strings.HasSuffix(name, ".zip") &&
			strings.HasPrefix(name, "english-wordnet-") &&
			!strings.Contains(name, "-plus")
	})
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to get latest English WordNet release")
	}

	// Get the dictionary path in ~/.crs-toolchain, named after the release tag and
	// asset. The asset name is included because a release can gain, lose, or
	// rename assets without its tag changing; keying the cache on the tag alone
	// would silently keep serving a stale, differently-formatted dictionary in
	// that case.
	dictionaryPath, err := utils.GetCacheFilePath(dictionaryCacheKey(tag, assetName))
	if err != nil {
		logger.Fatal().Err(err).Msg("Error getting dictionary path")
	}

	// Check if the dictionary exists, if not, download it
	if _, err := os.Stat(dictionaryPath); os.IsNotExist(err) {
		logger.Debug().Msgf("Downloading English WordNet %s (%s) from %s to %s", tag, assetName, downloadURL, dictionaryPath)
		if err := utils.DownloadFile(dictionaryPath, downloadURL); err != nil {
			logger.Fatal().Err(err).Msg("Failed to download dictionary")
		}
		logger.Debug().Msg("Download complete.")
	} else {
		logger.Debug().Msgf("Dictionary for %s (%s) found, skipping download.", tag, assetName)
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

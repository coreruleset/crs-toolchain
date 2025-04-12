// Copyright 2025 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
)

type FpFinderError struct{}

const dictionaryURL = "https://raw.githubusercontent.com/dwyl/english-words/master/words_alpha.txt"
const dictionaryFileName = "words_alpha.txt"
const minSize = 3

func (t *FpFinderError) Error() string {
	return "FpFinder error"
}

type FpFinder struct{}

func NewFpFinder() *FpFinder {
	return &FpFinder{}
}

func (t *FpFinder) FpFinder(inputFilePath string, extendedDictionaryFilePath string) error {
	// Get the dictionary path in ~/.crs-toolchain
	dictionaryPath, err := t.getDictionaryPath()
	if err != nil {
		logger.Fatal().Err(err).Msgf("Error getting dictionary path: %v", err)
	}

	// Check if the dictionary exists, if not, download it
	if _, err := os.Stat(dictionaryPath); os.IsNotExist(err) {
		logger.Debug().Msg("Dictionary file not found. Downloading...")
		if err := t.downloadFile(dictionaryPath, dictionaryURL); err != nil {
			logger.Fatal().Err(err).Msg("Failed to download dictionary")
		}
		logger.Debug().Msg("Download complete.")
	} else {
		logger.Debug().Msg("Dictionary file found, skipping download.")
	}

	// Load dictionary into memory
	englishDict, err := t.loadDictionary(dictionaryPath, minSize)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to load english dictionary")
	}

	var dict map[string]struct{}
	if extendedDictionaryFilePath != "" {
		extendedDict, err := t.loadDictionary(extendedDictionaryFilePath, 0)
		if err != nil {
			logger.Fatal().Err(err).Msg("Failed to load extended dictionary")
		}

		// Add words from the embedded extendedDictionary
		dict = t.mergeDictionaries(englishDict, extendedDict)
	} else {
		dict = englishDict
	}

	// Load input file into memory
	inputFile, err := t.loadFileContent(inputFilePath)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to load input file")
	}

	// Filter words not in dictionary, remove duplicates, and sort alphabetically
	filteredWords := t.filterContent(inputFile, dict, minSize)

	// Remove adjacent duplicate words from the sorted list
	filteredWords = slices.Compact(filteredWords)

	sort.Slice(filteredWords, func(i, j int) bool {
		return strings.ToLower(filteredWords[i]) < strings.ToLower(filteredWords[j])
	})

	for _, str := range filteredWords {
		fmt.Println(str)
	}

	return nil
}

func (t *FpFinder) getDictionaryPath() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	crsToolchainDir := filepath.Join(homeDir, ".crs-toolchain")

	// Create ~/.crs-toolchain folder if it doesn't exist
	if _, err := os.Stat(crsToolchainDir); os.IsNotExist(err) {
		if err := os.MkdirAll(crsToolchainDir, 0755); err != nil {
			return "", err
		}
	}

	return filepath.Join(crsToolchainDir, dictionaryFileName), nil
}

func (t *FpFinder) downloadFile(filepath, url string) error {
	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download %s: bad status: %s", url, resp.Status)
	}

	_, err = io.Copy(out, resp.Body)
	return err
}

func (t *FpFinder) loadDictionary(path string, minSize int) (map[string]struct{}, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	content := make(map[string]struct{})
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if len(word) >= minSize {
			content[word] = struct{}{}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return content, nil
}

func (t *FpFinder) mergeDictionaries(a, b map[string]struct{}) map[string]struct{} {
	merged := make(map[string]struct{})

	for k := range a {
		merged[k] = struct{}{}
	}
	for k := range b {
		merged[k] = struct{}{}
	}

	return merged
}

func (t *FpFinder) loadFileContent(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	defer file.Close()

	var content []string

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		content = append(content, word)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return content, nil
}

func (t *FpFinder) filterContent(inputFile []string, dict map[string]struct{}, minSize int) []string {
	var commentPattern = regexp.MustCompile(`^\s*#`)
	var filteredWords []string
	for _, word := range inputFile {
		if commentPattern.MatchString(word) {
			continue
		}

		if word == "" || len(word) < minSize {
			continue
		}

		// If the word is not in the dictionary, add it to the filtered list
		if _, found := dict[word]; !found {
			filteredWords = append(filteredWords, word)
		}
	}

	return filteredWords
}

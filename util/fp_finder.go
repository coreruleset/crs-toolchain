// Copyright 2025 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"bufio"
	_ "embed"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type FpFinderError struct{}

//go:embed english-extended.txt
var extendedDictionnary string

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

func (t *FpFinder) FpFinder(inputFilePath string, sortEnabled bool, uniqEnabled bool) error {
	// Get the dictionary path in ~/.crs-toolchain
	dictionaryPath, err := t.getDictionaryPath()
	if err != nil {
		logger.Fatal().Err(err).Msgf("Error getting dictionary path: %v", err)
	}

	// Check if the dictionary exists, if not, download it
	if _, err := os.Stat(dictionaryPath); os.IsNotExist(err) {
		logger.Debug().Msgf("Dictionary file not found. Downloading...")
		if err := t.downloadFile(dictionaryPath, dictionaryURL); err != nil {
			logger.Fatal().Err(err).Msgf("Failed to download dictionary: %v", err)
		}
		logger.Debug().Msgf("Download complete.")
	} else {
		logger.Debug().Msgf("Dictionary file found, skipping download.")
	}

	// Load dictionary into memory
	dict, err := t.loadDictionnary(dictionaryPath, minSize)
	if err != nil {
		logger.Fatal().Err(err).Msgf("Failed to load dictionary: %v", err)
	}

	// Load input file into memory
	inputFile, err := t.loadFileContent(inputFilePath)
	if err != nil {
		logger.Fatal().Err(err).Msgf("Failed to load input file: %v", err)
	}

	// Filter words not in dictionary, remove duplicates, and sort alphabetically
	filteredWords := t.filterContent(inputFile, dict, minSize)

	if uniqEnabled {
		filteredWords = t.removeDuplicates(filteredWords)
	}

	if sortEnabled {
		sort.Slice(filteredWords, func(i, j int) bool {
			return strings.ToLower(filteredWords[i]) < strings.ToLower(filteredWords[j])
		})
	}

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
		return fmt.Errorf("bad status: %s", resp.Status)
	}

	_, err = io.Copy(out, resp.Body)
	return err
}

func (t *FpFinder) loadDictionnary(path string, minSize int) (map[string]struct{}, error) {
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

	// Add words from the embedded extendedDictionnary
	for _, word := range strings.Split(extendedDictionnary, "\n") {
		word = strings.TrimSpace(word)
		content[word] = struct{}{}
	}

	return content, nil
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

func (t *FpFinder) removeDuplicates(input []string) []string {
	seen := make(map[string]struct{})
	var result []string

	for _, item := range input {
		if _, exists := seen[item]; !exists {
			seen[item] = struct{}{}
			result = append(result, item)
		}
	}

	return result
}

func (t *FpFinder) filterContent(inputFile []string, dict map[string]struct{}, minSize int) []string {
	var filteredWords []string
	for _, word := range inputFile {
		if strings.HasPrefix(word, "#") {
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

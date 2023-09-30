// Copyright 2023 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"bufio"
	"bytes"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

type inclusionLine struct {
	line  string
	order int
}

type inclusionLineSlice []inclusionLine

type inclusionLineMap map[string]inclusionLine

func (h inclusionLineSlice) Less(i, j int) bool {
	return h[i].order < h[j].order
}

func (h inclusionLineSlice) Len() int {
	return len(h)
}

func (h inclusionLineSlice) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
}

func buildIncludeString(parser *Parser, parsedLine ParsedLine) (string, error) {
	includeFileName := parsedLine.result[0]
	content, _ := parseFile(parser, includeFileName, nil)

	return replaceSuffixes(content, parsedLine.result[1])
}

func buildIncludeExceptString(parser *Parser, parsedLine ParsedLine) (string, error) {
	includeFileName := parsedLine.result[0]
	replacer := regexp.MustCompile(`\s+`)
	excludeFileNamesString := replacer.ReplaceAllString(parsedLine.result[1], " ")
	excludeFileNames := strings.Split(excludeFileNamesString, " ")

	// 1. build a map with lines as keys for fast access;
	//    store the line itself and its position in the value (an inclusionLine) for later
	// 2. remove exclusions from the map
	// 3. put the inclusionLines back into an array, still out of order
	// 4. build the resulting string by sorting the array and joining the lines
	includeMap, definitions := buildinclusionLineMap(parser, includeFileName)
	removeExclusions(parser, excludeFileNames, includeMap, definitions)

	inclusionLines := make(inclusionLineSlice, 0, len(includeMap))
	for _, value := range includeMap {
		inclusionLines = append(inclusionLines, value)
	}

	contentWithoutExclusions := stringFromInclusionLines(inclusionLines)
	return replaceSuffixes(bytes.NewBufferString(contentWithoutExclusions), parsedLine.result[2])
}

func buildPairMap(input string) (map[string]string, error) {
	replacer := regexp.MustCompile(`\s+`)
	cleanInput := replacer.ReplaceAllString(input, " ")
	logger.Trace().Msgf("Building pair map for: %s", cleanInput)
	list := strings.Split(cleanInput, " ")
	if len(list)%2 > 0 {
		return nil, fmt.Errorf("uneven number of arguments found: %s", cleanInput)
	}

	pairMap := map[string]string{}
	for i := 0; i < len(list); i += 2 {
		pairMap[list[i]] = list[i+1]
	}

	logger.Trace().Msgf("Built pair map: %v", pairMap)
	return pairMap, nil
}

func replaceSuffixes(inputLines *bytes.Buffer, suffixReplacementsInput string) (string, error) {
	if len(suffixReplacementsInput) == 0 {
		return inputLines.String(), nil
	}

	suffixReplacements, err := buildPairMap(suffixReplacementsInput)
	if err != nil {
		return "", err
	}

	var sb strings.Builder
	scanner := bufio.NewScanner(inputLines)
	scanner.Split(bufio.ScanLines)
	skipRegex := regexp.MustCompile(`^(?:##!|\s*$)`)
	for scanner.Scan() {
		entry := scanner.Text()
		if !skipRegex.MatchString(entry) {
			for match, replacement := range suffixReplacements {
				var found bool
				entry, found = strings.CutSuffix(entry, match)
				if found {
					entry += replacement
				}
			}
		}
		sb.WriteString(entry)
		sb.WriteRune('\n')
	}
	return sb.String(), nil
}

func removeExclusions(parser *Parser, excludeFileNames []string, includeMap map[string]inclusionLine, definitions map[string]string) {
	for _, fileName := range excludeFileNames {
		logger.Debug().Msgf("Processing exclusions from %s", fileName)
		excludeContent, _ := parseFile(parser, fileName, definitions)
		scanner := bufio.NewScanner(excludeContent)
		scanner.Split(bufio.ScanLines)
		for scanner.Scan() {
			exclusion := scanner.Text()
			delete(includeMap, exclusion)
			logger.Debug().Msgf("Excluded entry from include file: %s", exclusion)
		}
	}
}

func buildinclusionLineMap(parser *Parser, includeFileName string) (inclusionLineMap, map[string]string) {
	includeContent, definitions := parseFile(parser, includeFileName, nil)
	includeScanner := bufio.NewScanner(includeContent)
	includeScanner.Split(bufio.ScanLines)
	includeMap := make(inclusionLineMap, 100)
	index := 0
	for includeScanner.Scan() {
		entry := includeScanner.Text()
		includeMap[entry] = inclusionLine{entry, index}
		index++
	}
	return includeMap, definitions
}

func stringFromInclusionLines(inclusionLines inclusionLineSlice) string {
	// Ensure that the last line is always empty.
	// Corresponds to "regular" lines in the parser, to which `\n` is appended
	length := len(inclusionLines)
	if length == 0 {
		return ""
	} else if length == 1 {
		return inclusionLines[0].line + "\n"
	}

	sort.Sort(inclusionLines)
	var stringBuilder strings.Builder
	stringBuilder.Grow(len(inclusionLines) * 20)
	stringBuilder.WriteString(inclusionLines[0].line)
	for _, h := range inclusionLines[1:] {
		stringBuilder.WriteString("\n")
		stringBuilder.WriteString(h.line)
	}
	stringBuilder.WriteString("\n")

	return stringBuilder.String()
}

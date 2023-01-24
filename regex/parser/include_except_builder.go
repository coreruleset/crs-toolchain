// Copyright 2023 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"bufio"
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

func buildIncludeExceptString(parser *Parser, parsedLine ParsedLine) string {
	includeFileName := parsedLine.result[0]
	excludeFileName := parsedLine.result[1]

	// 1. build a map with lines as keys for fast access;
	//    store the line itself and its position in the value (a inclusionLine) for later
	// 2. remove exclusions from the map
	// 3. put the inclusionLines back into an array, still out of order
	// 4. build the resulting string by sorting the array and joining the lines
	includeMap := buildinclusionLineMap(parser, includeFileName)
	removeExclusions(parser, excludeFileName, includeMap)

	inclusionLines := make(inclusionLineSlice, 0, len(includeMap))
	for _, value := range includeMap {
		inclusionLines = append(inclusionLines, value)
	}

	return stringFromInclusionLines(inclusionLines)
}

func removeExclusions(parser *Parser, excludeFileName string, includeMap map[string]inclusionLine) {
	excludeContent, _ := parseFile(parser, excludeFileName)
	scanner := bufio.NewScanner(excludeContent)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		exclusion := scanner.Text()
		delete(includeMap, exclusion)
	}
}

func buildinclusionLineMap(parser *Parser, includeFileName string) inclusionLineMap {
	includeContent, _ := parseFile(parser, includeFileName)
	includeScanner := bufio.NewScanner(includeContent)
	includeScanner.Split(bufio.ScanLines)
	includeMap := make(inclusionLineMap, 100)
	index := 0
	for includeScanner.Scan() {
		entry := includeScanner.Text()
		includeMap[entry] = inclusionLine{entry, index}
		index++
	}
	return includeMap
}

func stringFromInclusionLines(inclusionLines inclusionLineSlice) string {
	sort.Sort(inclusionLines)
	var stringBuilder strings.Builder
	stringBuilder.Grow(len(inclusionLines) * 20)
	stringBuilder.WriteString(inclusionLines[0].line)
	for _, h := range inclusionLines[1:] {
		stringBuilder.WriteString("\n")
		stringBuilder.WriteString(h.line)
	}
	return stringBuilder.String()
}

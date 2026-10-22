// Copyright 2026 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package format

import (
	"fmt"
	"sort"
	"strings"

	"github.com/coreruleset/crs-toolchain/v2/regex"
)

// Groups shorter than this are not worth a definition.
const minDefinitionLength = 20

type suggestion struct {
	line    int
	message string
}

// findSuggestions inspects the lines of every assemble block and suggests
// structural changes that let the assembler do its job: one alternative per
// line, no hand-factored groups, definitions for repeated groups and no
// duplicate lines. Line numbers are 1-based.
func findSuggestions(lines []string) []suggestion {
	var suggestions []suggestion
	var blocks []string
	var block []int // line indexes of the current assemble block

	for i, raw := range lines {
		line := strings.TrimSpace(raw)
		if matches := blockStartRegex.FindStringSubmatch(line); matches != nil {
			if len(blocks) > 0 && blocks[len(blocks)-1] == "assemble" {
				suggestions = append(suggestions, blockSuggestions(lines, block)...)
				block = nil
			}
			blocks = append(blocks, matches[1])
			continue
		}
		if blockEndRegex.MatchString(line) {
			if len(blocks) > 0 && blocks[len(blocks)-1] == "assemble" {
				suggestions = append(suggestions, blockSuggestions(lines, block)...)
				block = nil
			}
			if len(blocks) > 0 {
				blocks = blocks[:len(blocks)-1]
			}
			continue
		}
		// Lines on either side of an output marker are concatenated, not alternated.
		if assembleOutputRegex.MatchString(line) {
			suggestions = append(suggestions, blockSuggestions(lines, block)...)
			block = nil
			continue
		}
		if len(blocks) == 0 || blocks[len(blocks)-1] != "assemble" || line == "" || strings.HasPrefix(line, "##!") {
			continue
		}
		block = append(block, i)
		suggestions = append(suggestions, lineSuggestions(i+1, line)...)
	}

	sort.SliceStable(suggestions, func(a, b int) bool { return suggestions[a].line < suggestions[b].line })
	return suggestions
}

func lineSuggestions(lineNumber int, line string) []suggestion {
	topPipes, groups, ok := regex.ScanGroups(line)
	if !ok {
		return nil
	}

	if len(topPipes) > 0 {
		return []suggestion{{lineNumber, "alternatives belong on separate lines:" + listLines(regex.SplitAt(line, 0, len(line), topPipes))}}
	}

	var alternations []regex.Group
	for _, group := range groups {
		if group.IsOutermost(groups) && len(group.Pipes) > 0 {
			alternations = append(alternations, group)
		}
	}
	if len(alternations) != 1 {
		return nil
	}
	alternation := alternations[0]
	if !alternation.Expandable(line) {
		return nil
	}
	alternatives := alternation.Alternatives(line)
	// A group of single tokens, such as `(?:\W|^)`, is an idiom; expanding it
	// only repeats the rest of the line.
	allTokens := true
	for _, alternative := range alternatives {
		allTokens = allTokens && regex.IsToken(alternative)
	}
	if allTokens {
		return nil
	}
	var expanded []string
	for _, alternative := range alternatives {
		expanded = append(expanded, line[:alternation.Start]+alternative+line[alternation.End:])
	}
	return []suggestion{{lineNumber, "the assembler can factor this group; write one line per alternative:" + listLines(expanded)}}
}

// blockSuggestions reports duplicate lines and groups that appear more than
// once in the same assemble block.
func blockSuggestions(lines []string, block []int) []suggestion {
	var suggestions []suggestion
	firstSeen := map[string]int{}
	occurrences := map[string][]int{}
	var candidates []string

	for _, i := range block {
		line := strings.TrimSpace(lines[i])
		if first, seen := firstSeen[line]; seen {
			suggestions = append(suggestions, suggestion{i + 1, fmt.Sprintf("duplicate of line %d", first)})
			continue
		}
		firstSeen[line] = i + 1

		_, groups, ok := regex.ScanGroups(line)
		if !ok {
			continue
		}
		for _, group := range groups {
			text := line[group.Start:group.End]
			if len(text) < minDefinitionLength {
				continue
			}
			if occurrences[text] == nil {
				candidates = append(candidates, text)
			}
			occurrences[text] = append(occurrences[text], i+1)
		}
	}

	// Longest first, so that the parts of a repeated group are not reported again.
	sort.SliceStable(candidates, func(a, b int) bool { return len(candidates[a]) > len(candidates[b]) })
	var reported []string
	for _, text := range candidates {
		if len(occurrences[text]) < 2 || containedIn(text, reported) {
			continue
		}
		reported = append(reported, text)
		suggestions = append(suggestions, suggestion{
			occurrences[text][0],
			fmt.Sprintf("group appears %d times (line %s); consider `##!> define <name> %s`",
				len(occurrences[text]), joinInts(occurrences[text]), text),
		})
	}
	return suggestions
}

func containedIn(text string, others []string) bool {
	for _, other := range others {
		if strings.Contains(other, text) {
			return true
		}
	}
	return false
}

func listLines(lines []string) string {
	return "\n  " + strings.Join(lines, "\n  ")
}

// joinInts joins sorted numbers, skipping repeats.
func joinInts(numbers []int) string {
	var parts []string
	for i, n := range numbers {
		if i == 0 || n != numbers[i-1] {
			parts = append(parts, fmt.Sprint(n))
		}
	}
	return strings.Join(parts, ", ")
}

// Copyright 2026 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package format

import (
	"fmt"
	"sort"
	"strings"
)

// Groups shorter than this are not worth a definition.
const minDefinitionLength = 20

type suggestion struct {
	line    int
	message string
}

type group struct {
	start, end int   // line[start:end] is the group, parentheses included
	pipes      []int // positions of the `|` directly inside the group
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
	topPipes, groups, ok := scanGroups(line)
	if !ok {
		return nil
	}

	if len(topPipes) > 0 {
		return []suggestion{{lineNumber, "alternatives belong on separate lines:" + listLines(splitAt(line, 0, len(line), topPipes))}}
	}

	var alternations []group
	for _, g := range groups {
		if isOutermost(g, groups) && len(g.pipes) > 0 {
			alternations = append(alternations, g)
		}
	}
	if len(alternations) != 1 {
		return nil
	}
	g := alternations[0]
	if !expandable(line, g) {
		return nil
	}
	alternatives := splitAt(line, g.start+3, g.end-1, g.pipes)
	// A group of single tokens, such as `(?:\W|^)`, is an idiom; expanding it
	// only repeats the rest of the line.
	allTokens := true
	for _, alternative := range alternatives {
		allTokens = allTokens && isToken(alternative)
	}
	if allTokens {
		return nil
	}
	var expanded []string
	for _, alternative := range alternatives {
		expanded = append(expanded, line[:g.start]+alternative+line[g.end:])
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

		_, groups, ok := scanGroups(line)
		if !ok {
			continue
		}
		for _, g := range groups {
			text := line[g.start:g.end]
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

// scanGroups finds the `|` at the top level of a line and every parenthesized
// group in it. It skips escapes, character classes and `{{definitions}}`.
// Returns false if the parentheses don't balance.
func scanGroups(line string) (topPipes []int, groups []group, ok bool) {
	var open []group
	for i := 0; i < len(line); i++ {
		switch {
		case line[i] == '\\':
			i++
		case line[i] == '[':
			i = classEnd(line, i)
			if i < 0 {
				return nil, nil, false
			}
		case strings.HasPrefix(line[i:], "{{"):
			end := strings.Index(line[i:], "}}")
			if end < 0 {
				return nil, nil, false
			}
			i += end + 1
		case line[i] == '(':
			open = append(open, group{start: i})
		case line[i] == ')':
			if len(open) == 0 {
				return nil, nil, false
			}
			g := open[len(open)-1]
			open = open[:len(open)-1]
			g.end = i + 1
			groups = append(groups, g)
		case line[i] == '|':
			if len(open) == 0 {
				topPipes = append(topPipes, i)
			} else {
				open[len(open)-1].pipes = append(open[len(open)-1].pipes, i)
			}
		}
	}
	return topPipes, groups, len(open) == 0
}

// classEnd returns the index of the `]` closing the character class that
// starts at line[start], or -1.
func classEnd(line string, start int) int {
	i := start + 1
	if i < len(line) && line[i] == '^' {
		i++
	}
	if i < len(line) && line[i] == ']' {
		i++
	}
	for ; i < len(line); i++ {
		switch {
		case line[i] == '\\':
			i++
		case strings.HasPrefix(line[i:], "[:"):
			end := strings.Index(line[i:], ":]")
			if end < 0 {
				return -1
			}
			i += end + 1
		case line[i] == ']':
			return i
		}
	}
	return -1
}

// expandable reports whether a group can be distributed over its
// alternatives: a non-capturing group without a quantifier. Expanding a
// capturing group would change what the rule captures.
func expandable(line string, g group) bool {
	if !strings.HasPrefix(line[g.start:], "(?:") {
		return false
	}
	if g.end < len(line) {
		next := line[g.end]
		if next == '?' || next == '*' || next == '+' || (next == '{' && !strings.HasPrefix(line[g.end:], "{{")) {
			return false
		}
	}
	return true
}

// isToken reports whether s is a single character, escape, character class
// or definition.
func isToken(s string) bool {
	switch {
	case len(s) == 1:
		return true
	case len(s) == 2 && s[0] == '\\':
		return true
	case strings.HasPrefix(s, "["):
		return classEnd(s, 0) == len(s)-1
	case strings.HasPrefix(s, "{{"):
		return strings.Index(s, "}}") == len(s)-2
	}
	return false
}

func isOutermost(g group, groups []group) bool {
	for _, other := range groups {
		if other.start < g.start && g.end < other.end {
			return false
		}
	}
	return true
}

func splitAt(line string, start, end int, pipes []int) []string {
	var parts []string
	for _, pipe := range pipes {
		parts = append(parts, line[start:pipe])
		start = pipe + 1
	}
	return append(parts, line[start:end])
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

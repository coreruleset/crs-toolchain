// Copyright 2026 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package regex

import "strings"

// Group is a parenthesized group found by ScanGroups.
type Group struct {
	Start, End int   // line[Start:End] is the group, parentheses included
	Pipes      []int // positions of the `|` directly inside the group
}

// ScanGroups finds the `|` at the top level of a line and every parenthesized
// group in it. It skips escapes, character classes and `{{definitions}}`.
// Returns false if the parentheses don't balance.
func ScanGroups(line string) (topPipes []int, groups []Group, ok bool) {
	var open []Group
	for i := 0; i < len(line); i++ {
		switch {
		case line[i] == '\\':
			i++
		case line[i] == '[':
			i = ClassEnd(line, i)
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
			open = append(open, Group{Start: i})
		case line[i] == ')':
			if len(open) == 0 {
				return nil, nil, false
			}
			g := open[len(open)-1]
			open = open[:len(open)-1]
			g.End = i + 1
			groups = append(groups, g)
		case line[i] == '|':
			if len(open) == 0 {
				topPipes = append(topPipes, i)
			} else {
				open[len(open)-1].Pipes = append(open[len(open)-1].Pipes, i)
			}
		}
	}
	return topPipes, groups, len(open) == 0
}

// ClassEnd returns the index of the `]` closing the character class that
// starts at line[start], or -1. A `]` directly after the opening `[` or `[^`
// is a literal, as are escaped brackets and the brackets of a POSIX class
// such as `[:alpha:]`.
func ClassEnd(line string, start int) int {
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

// IsToken reports whether s is a single character, escape, character class
// or `{{definition}}`.
func IsToken(s string) bool {
	switch {
	case len(s) == 1:
		return true
	case len(s) == 2 && s[0] == '\\':
		return true
	case strings.HasPrefix(s, "["):
		return ClassEnd(s, 0) == len(s)-1
	case strings.HasPrefix(s, "{{"):
		return strings.Index(s, "}}") == len(s)-2
	}
	return false
}

// IsOutermost reports whether no group in groups encloses g.
func (g Group) IsOutermost(groups []Group) bool {
	for _, other := range groups {
		if other.Start < g.Start && g.End < other.End {
			return false
		}
	}
	return true
}

// Expandable reports whether the group can be distributed over its
// alternatives without changing the meaning of line: it is non-capturing
// and not followed by a quantifier.
func (g Group) Expandable(line string) bool {
	if !strings.HasPrefix(line[g.Start:], "(?:") {
		return false
	}
	if g.End < len(line) {
		next := line[g.End]
		if next == '?' || next == '*' || next == '+' || (next == '{' && !strings.HasPrefix(line[g.End:], "{{")) {
			return false
		}
	}
	return true
}

// Alternatives returns the alternatives of a `(?:…)` group, without the
// parentheses and the `?:` prefix.
func (g Group) Alternatives(line string) []string {
	return SplitAt(line, g.Start+3, g.End-1, g.Pipes)
}

// SplitAt splits line[start:end] at the given positions, dropping the
// character at each position.
func SplitAt(line string, start, end int, pipes []int) []string {
	var parts []string
	for _, pipe := range pipes {
		parts = append(parts, line[start:pipe])
		start = pipe + 1
	}
	return append(parts, line[start:end])
}

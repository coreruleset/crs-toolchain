// Copyright 2026 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package format

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func suggestionsFor(contents string) []suggestion {
	return findSuggestions(strings.Split(contents, "\n"))
}

// The MySQL lines of 942550.ra before review on coreruleset/coreruleset#4853 (fb65491).
func TestFindSuggestions_942550(t *testing.T) {
	got := suggestionsFor(`##!> assemble
  (?:^(?:(?:or|xor)(?:not)?|andnot|[0-9]+(?:and|or|xor)(?:not)?)?|[^a-z0-9_](?:(?:[0-9]+)?(?:and|or|xor)(?:not)?)?)json_extract\b[^\(]*\([^)]*\)
  {{quotes}}(?:/\*[^*]*\*+(?:[^*/][^*]*\*+){0,8}/)?member(?:/\*[^*]*\*+(?:[^*/][^*]*\*+){0,8}/)?of(?:\((?:[\"'` + "`" + `\[{(@+\-.0-9]|/\*|null|true|false)|/\*|#|--)
##!<`)

	assert.Len(t, got, 3)
	assert.Equal(t, 2, got[0].line)
	assert.Contains(t, got[0].message, "\n  ^(?:(?:or|xor)(?:not)?|andnot|[0-9]+(?:and|or|xor)(?:not)?)?json_extract\\b[^\\(]*\\([^)]*\\)\n")
	assert.Contains(t, got[0].message, "\n  [^a-z0-9_](?:(?:[0-9]+)?(?:and|or|xor)(?:not)?)?json_extract\\b[^\\(]*\\([^)]*\\)")
	// The trailing group of line 3 can be expanded too.
	assert.Equal(t, 3, got[1].line)
	assert.Contains(t, got[1].message, "the assembler can factor this group")
	assert.Equal(t, 3, got[2].line)
	assert.Equal(t, "group appears 2 times (line 3); consider `##!> define <name> (?:/\\*[^*]*\\*+(?:[^*/][^*]*\\*+){0,8}/)`", got[2].message)
}

func TestFindSuggestions(t *testing.T) {
	tests := []struct {
		name     string
		contents string
		want     []string
	}{
		{"one alternative per line", "##!> assemble\n  foo\n  bar(?:baz)?\n##!<", nil},
		{"top-level alternation", "##!> assemble\n  foo|bar\n##!<", []string{"2: alternatives belong on separate lines:\n  foo\n  bar"}},
		{"hand-factored group", "##!> assemble\n  a(?:bb|c)d\n##!<", []string{"2: the assembler can factor this group; write one line per alternative:\n  abbd\n  acd"}},
		{"quantified group", "##!> assemble\n  a(?:b|c)?d\n  a(?:b|c){2}d\n##!<", nil},
		{"definition after group", "##!> assemble\n  (?:bb|cc){{d}}\n##!<", []string{"2: the assembler can factor this group; write one line per alternative:\n  bb{{d}}\n  cc{{d}}"}},
		{"group of single tokens", "##!> assemble\n  (?:\\W|^)data:\n  (?:[<=>]|{{quotes}}|a)b\n##!<", nil},
		{"capturing group", "##!> assemble\n  a(bb|cc)d\n##!<", nil},
		{"lookahead", "##!> assemble\n  a(?=b|c)\n##!<", nil},
		{"two groups", "##!> assemble\n  (?:a|b)(?:c|d)\n##!<", nil},
		{"pipes that are not alternations", `##!> assemble
  a\|b
  [|]c
  []|]d
  [^]|]e
  [[:alpha:]|]f
##!<`, nil},
		{"duplicate", "##!> assemble\n  foo\n  bar\n  foo\n##!<", []string{"4: duplicate of line 2"}},
		{"duplicate across output marker", "##!> assemble\n  foo\n  ##!=>\n  foo\n##!<", nil},
		{"outside assemble", "foo|bar\n##!> cmdline unix\n  foo|bar\n##!<", nil},
		{"comments", "##!> assemble\n  ##! foo|bar\n##!<", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []string
			for _, s := range suggestionsFor(tt.contents) {
				got = append(got, fmt.Sprintf("%d: %s", s.line, s.message))
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGithubEscaper(t *testing.T) {
	assert.Equal(t, "%2525c0%0A  %250a", githubEscaper.Replace("%25c0\n  %0a"))
}

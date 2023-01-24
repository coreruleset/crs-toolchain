// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package regex

import "regexp"

// IncludeRegex matches an include processor line (##! include <value>).
// The value is captured in group 1.
var IncludeRegex = regexp.MustCompile(`^##!>\s*include\s+(\S+)\s*$`)

// IncludeExceptRegex matches an include-except processor line (##! include-except <value1> <value2>).
// The first value is captured in group 1, the second in group 2.
var IncludeExceptRegex = regexp.MustCompile(`^##!>\s*include-except\s+(\S+)\s+(\S+)\s*$`)

// DefinitionRegex matches a definition processor line (##! define <name> <value>)
// The name is captured in group 1, the value in group 2.
var DefinitionRegex = regexp.MustCompile(`^##!>\s*define\s+([a-zA-Z0-9-_]+)\s+(.*)$`)

// CommentRegex matches a comment line (##!, no other directives)
var CommentRegex = regexp.MustCompile(`^##!(?:[^^$+><=]|$)`)

// FlagsRegex matches a flags line (##!+ <value>).
// The value is captured in group 1.
var FlagsRegex = regexp.MustCompile(`^##!\+\s*(.*)\s*$`)

// PrefixRegex matches a prefix line (##!^ <value>)
// The value is captured in group 1.
var PrefixRegex = regexp.MustCompile(`^##!\^\s*(.*)$`)

// SuffixRegex matches a suffix line (##!$ <value>)
// The value is captured in group 1.
var SuffixRegex = regexp.MustCompile(`^##!\$\s*(.*)$`)

// ProcessorStartRegex matches any processor start line (##! assemble, ##! define <name> <value>).
// The name is captured in group 1, the optional value in group 2.
var ProcessorStartRegex = regexp.MustCompile(`^##!>\s*([a-z]+)(?:\s+([a-z]+))?`)

// ProcessorBlockStartRegex matches any processor start line, where the processor has a body
// (##! assemble, ##! cmdline <value>).
// The name is captured in group 1, the optional value is captured in group 2.
var ProcessorBlockStartRegex = regexp.MustCompile(`^##!>\s*(assemble|cmdline)\s*(\S+)?`)

// ProcessorEndRegex matches a processor end line (##!<)
var ProcessorEndRegex = regexp.MustCompile(`^##!<`)

// AssembleInputRegex matches an input line of the assemble processor (##!=< <name>).
// The name is captured in group 1.
var AssembleInputRegex = regexp.MustCompile(`^\s*##!=<\s*(.*)$`)

// AssembleOutputRegex matches an output line of the assemble processor (##!=> <name>).
// The name is captured in group 1, the optional output in group 2.
var AssembleOutputRegex = regexp.MustCompile(`^\s*##!=>\s*(.*)$`)

// RuleRxRegex matches a full SecRule line with @rx.
// Everything up to the start of the regular expression is captured in group 1,
// the end of the line after the regular expression is captured in group 2.
var RuleRxRegex = regexp.MustCompile(`(.*"!?@rx )(.*)(" \\)`)

// SecRuleRegex matches any SecRule line.
var SecRuleRegex = regexp.MustCompile(`\s*SecRule`)

// RuleIdFileNameRegex matches the rule ID in a regex-assembly file name (<id>-<chain>.ra).
// The rule ID is captured in group 1, the optional chain offset in group2,
// and the optional extension in group 3.
var RuleIdFileNameRegex = regexp.MustCompile(`^(\d{6})(?:-chain(\d+))?(?:\.ra)?$`)

// RuleIdTestFileNameRegex matches the rule ID in a test file name (<id>.yaml).
// The rule ID is captured in group 1, the optional extension in group 2.
var RuleIdTestFileNameRegex = regexp.MustCompile(`^(\d{6})(?:\.ya?ml)?$`)

// TestTitleRegex matches any test_title line in test YAML files (test_title: "<title>").
// Everything up to the value of the test title is captured in group 1.
var TestTitleRegex = regexp.MustCompile(`(.*test_title:\s*)"?[^"]+"?\s*$`)

// DefinitionReferenceRegex matches any reference to a definition.
// The matched reference name will be captured in group 1.
var DefinitionReferenceRegex = regexp.MustCompile(`{{([a-zA-Z0-9-_]+)}}`)

// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package regex

import "regexp"

var IncludeRegex = regexp.MustCompile(`^##!>\s*include\s*(.*)$`)
var DefinitionRegex = regexp.MustCompile(`^##!>\s*define\s+([a-zA-Z0-9-_]+)\s+(.*)$`)
var CommentRegex = regexp.MustCompile(`^##![^^$+><=]`)
var FlagsRegex = regexp.MustCompile(`^##!\+\s*(.*)\s*$`)
var PrefixRegex = regexp.MustCompile(`^##!\^\s*(.*)$`)
var SuffixRegex = regexp.MustCompile(`^##!\$\s*(.*)$`)
var ProcessorStartRegex = regexp.MustCompile(`^##!>\s*([a-z]+)(?:\s+([a-z]+))?`)
var ProcessorBlockStartRegex = regexp.MustCompile(`^##!>\s*(assemble|cmdline)\s*(\S+)?`)
var ProcessorEndRegex = regexp.MustCompile(`^##!<`)
var AssembleInputRegex = regexp.MustCompile(`^\s*##!=<\s*(.*)$`)
var AssembleOutputRegex = regexp.MustCompile(`^\s*##!=>\s*(.*)$`)

var RuleRxRegex = regexp.MustCompile(`(.*"!?@rx ).*(" \\)`)
var SecRuleRegex = regexp.MustCompile(`\s*SecRule`)
var RuleIdRegex = regexp.MustCompile(`^(\d{6})(?:-chain(\d+))?(?:\.data)?$`)

var TestTitleRegex = regexp.MustCompile(`(.*test_title:\s*)"?([^"]+)"?\s*$`)

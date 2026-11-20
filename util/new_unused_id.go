// Copyright 2026 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"

	"github.com/coreruleset/crs-toolchain/v2/context"
)

var rangeRegex = regexp.MustCompile(`^[0-9]{3}$`)

// ruleIdRegex matches the `id` action: it follows a quote or a comma, or starts
// a (possibly commented-out) line. An `id:` in operator or message text doesn't.
var ruleIdRegex = regexp.MustCompile(`(?m)(?:^\s*#?\s*|["',])id:\s*\\?['"]?(\d{6})`)

// NewUnusedId returns the ID for a new rule in the range of a 3-digit prefix
// (e.g., "942" for 942000-942999): the next multiple of 10 above the highest
// ID in use, and at least XXX100, since XXX000-XXX099 hold the flow-control
// rules. Gaps are never filled: they belong to removed rules, and existing
// exclusions such as `SecRuleRemoveById` may still refer to them.
// ponytail: only the current rule files are checked; if the highest rule in a
// range was removed, its ID comes back. Check git history if that matters.
func NewUnusedId(rangePrefix string, ctxt *context.Context) (string, error) {
	if !rangeRegex.MatchString(rangePrefix) {
		return "", fmt.Errorf("range must be exactly 3 digits, got: %s", rangePrefix)
	}
	prefix, _ := strconv.Atoi(rangePrefix)

	ids, err := existingIds(ctxt)
	if err != nil {
		return "", err
	}

	found := false
	next := prefix*1000 + 100
	for _, id := range ids {
		if id/1000 != prefix {
			continue
		}
		found = true
		if id >= next {
			next = (id/10 + 1) * 10
		}
	}
	if !found {
		return "", fmt.Errorf("no rules found in range %s", rangePrefix)
	}
	if next/1000 != prefix {
		return "", fmt.Errorf("no unused IDs left in range %s", rangePrefix)
	}
	return strconv.Itoa(next), nil
}

// existingIds returns every rule ID in the rule files and in
// crs-setup.conf.example, including commented-out rules.
func existingIds(ctxt *context.Context) ([]int, error) {
	files, err := filepath.Glob(filepath.Join(ctxt.RulesDir(), "*.conf*"))
	if err != nil {
		return nil, err
	}
	files = append(files, filepath.Join(ctxt.RootDir(), "crs-setup.conf.example"))

	var ids []int
	for _, file := range files {
		content, err := os.ReadFile(file)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		for _, match := range ruleIdRegex.FindAllSubmatch(content, -1) {
			id, _ := strconv.Atoi(string(match[1]))
			ids = append(ids, id)
		}
	}
	return ids, nil
}

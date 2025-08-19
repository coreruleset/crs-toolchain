// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"errors"
	"strconv"
	"strings"

	"github.com/coreruleset/crs-toolchain/v2/regex"
)

func ParseRuleId(idAndChainOffset string, cmdContext *CommandContext) error {
	cmdContext.UseStdin = false

	subs := regex.RuleIdFileNameRegex.FindAllStringSubmatch(idAndChainOffset, -1)
	if subs == nil {
		return errors.New("failed to match rule ID")
	}

	fileName := subs[0][0]
	id := subs[0][1]
	chainOffsetString := subs[0][2]

	chainOffset, err := strconv.ParseUint(chainOffsetString, 10, 8)
	if err != nil && len(chainOffsetString) > 0 {
		return errors.New("failed to match chain offset. Value must not be larger than 255")
	}

	if !strings.HasSuffix(fileName, ".conf") {
		fileName += ".conf"
	}

	cmdContext.Id = id
	cmdContext.FileName = fileName
	cmdContext.ChainOffset = uint8(chainOffset)

	return nil
}

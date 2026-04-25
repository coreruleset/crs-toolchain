// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package regex

import (
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/coreruleset/crs-toolchain/v2/cmd/internal"
	"github.com/coreruleset/crs-toolchain/v2/cmd/regex/compare"
	"github.com/coreruleset/crs-toolchain/v2/cmd/regex/format"
	"github.com/coreruleset/crs-toolchain/v2/cmd/regex/generate"
	regexInternal "github.com/coreruleset/crs-toolchain/v2/cmd/regex/internal"
	"github.com/coreruleset/crs-toolchain/v2/cmd/regex/update"
)

var logger = log.With().Str("component", "cmd.regex").Logger()

func New(cmdContext *internal.CommandContext) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "regex",
		Short: "Commands that process regular expressions",
		Long: `The commands in this group all interact with regular expressions.
For example, they generate regular expressions from regex-assembly files, update regular expressions
in rule files, or compare the regular expressions in rule files against what would be
generated from the current regex-assembly file.`,
	}

	regexCmdContext := regexInternal.NewCommandContext(cmdContext, &logger)
	cmd.AddCommand(
		compare.New(regexCmdContext),
		format.New(regexCmdContext),
		generate.New(regexCmdContext),
		update.New(regexCmdContext),
	)

	return cmd
}

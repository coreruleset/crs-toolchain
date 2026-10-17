// Copyright 2026 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package newUnusedId

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/coreruleset/crs-toolchain/v2/cmd/internal"
	"github.com/coreruleset/crs-toolchain/v2/util"
)

func New(cmdContext *internal.CommandContext) *cobra.Command {
	return &cobra.Command{
		Use:   "new-unused-id RANGE",
		Short: "Print the ID to use for a new rule",
		Long: `Print the ID to use for a new rule in RANGE, the 3-digit prefix of the rule file
(e.g., 942 for REQUEST-942-APPLICATION-ATTACK-SQLI.conf).

The ID is the next multiple of 10 above the highest ID in use, and at least
RANGE100. IDs in all rule files and in crs-setup.conf.example count.
Gaps left by removed rules are never reused, because existing exclusions may
still refer to them. The history is not checked: if the highest rule in a
range was removed, its ID is handed out again.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			id, err := util.NewUnusedId(args[0], cmdContext.RootContext())
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), id)
			return err
		},
	}
}

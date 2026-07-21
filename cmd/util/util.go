// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"github.com/spf13/cobra"

	"github.com/coreruleset/crs-toolchain/v2/cmd/internal"
	fpFinder "github.com/coreruleset/crs-toolchain/v2/cmd/util/fp_finder"
	renumberTests "github.com/coreruleset/crs-toolchain/v2/cmd/util/renumber_tests"
	selfUpdate "github.com/coreruleset/crs-toolchain/v2/cmd/util/self_update"
)

func New(cmdContext *internal.CommandContext) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "util",
		Short: "Collection of utility commands",
		Args:  cobra.ExactArgs(1),
	}

	cmd.AddCommand(
		fpFinder.New(cmdContext),
		renumberTests.New(cmdContext),
		selfUpdate.New())

	return cmd
}

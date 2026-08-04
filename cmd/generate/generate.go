// Copyright 2025 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package generate

import (
	"github.com/spf13/cobra"

	phpFunctionNames "github.com/coreruleset/crs-toolchain/v2/cmd/generate/php_function_names"
	"github.com/coreruleset/crs-toolchain/v2/cmd/internal"
)

func New(cmdContext *internal.CommandContext) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Commands that generate data files used by CRS rules",
		Args:  cobra.ExactArgs(1),
	}

	cmd.AddCommand(
		phpFunctionNames.New(cmdContext),
	)

	return cmd
}

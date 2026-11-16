// Copyright 2026 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package plugin

import (
	"github.com/spf13/cobra"

	"github.com/coreruleset/crs-toolchain/v2/cmd/internal"
	"github.com/coreruleset/crs-toolchain/v2/cmd/plugin/install"
)

func New(cmdContext *internal.CommandContext) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "plugin",
		Short: "Manage CRS plugins",
		Args:  cobra.ExactArgs(1),
	}

	cmd.AddCommand(install.New(cmdContext))

	return cmd
}

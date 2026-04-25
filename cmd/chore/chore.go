// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package chore

import (
	"github.com/spf13/cobra"

	release "github.com/coreruleset/crs-toolchain/v2/cmd/chore/release"
	updateCopyright "github.com/coreruleset/crs-toolchain/v2/cmd/chore/update_copyright"
	"github.com/coreruleset/crs-toolchain/v2/cmd/internal"
)

func New(cmdContext *internal.CommandContext) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "chore",
		Short: "Collection of chore commands",
		Args:  cobra.ExactArgs(1),
	}

	cmd.AddCommand(
		updateCopyright.New(cmdContext),
		release.New(cmdContext),
	)

	return cmd
}

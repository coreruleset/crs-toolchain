// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package main

import (
	_ "github.com/coreruleset/crs-toolchain/logger"

	"github.com/coreruleset/crs-toolchain/cmd"
)

// nolint: gochecknoglobals
var (
	version = "dev"
	commit  = ""
	date    = ""
	builtBy = ""
)

func main() {
	cmd.Execute(version, commit, date, builtBy)

}

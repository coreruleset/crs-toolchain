// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"

	"github.com/theseion/crs-toolchain/v2/cmd"
)

func main() {
	os.Args = []string{"", "-d", "/Users/cthulu/dev/git/coreruleset", "regex", "generate", "932100"}
	cmd.Execute()
}

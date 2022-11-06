// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package main

import (
	_ "github.com/theseion/crs-toolchain/v2/logger"

	"github.com/theseion/crs-toolchain/v2/cmd"
)

func main() {
	cmd.Execute()
}

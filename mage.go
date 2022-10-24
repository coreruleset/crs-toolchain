// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

//go:build ignore
// +build ignore

// Entrypoint to mage for running without needing to install the command.
// https://magefile.org/zeroinstall/
package main

import (
	"os"

	"github.com/magefile/mage/mage"
)

func main() {
	os.Exit(mage.Main())
}

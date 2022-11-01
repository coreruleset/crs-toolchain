// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package processors

import (
	"fmt"
	"io"
	"os"
)

type Context struct {
	rootDirectory      string
	rulesDirectory     string
	utilDirectory      string
	dataFilesDirectory string
	includeFiles       string
	singleRuleID       int
	singleChainOffset  bool
}

// NewContext creates a new processor context using the `rootDir` as the root directory.
func NewContext(rootDir string) *Context {
	// check if directory exists first
	_, err := os.Stat(rootDir)
	if err != nil {
		logger.Fatal().Err(err).Msgf("creating context: problem using %s as base directory.", rootDir)
	}
	ctx := &Context{
		rootDirectory:      rootDir,
		rulesDirectory:     rootDir + "/rules",
		utilDirectory:      rootDir + "/util",
		dataFilesDirectory: rootDir + "/data",
		includeFiles:       rootDir + "/data/include",
		singleRuleID:       0,
		singleChainOffset:  false,
	}
	//self.single_rule_id = namespace.rule_id if namespace else None
	//self.single_chain_offset = None
	//if namespace and "chain_offset" in namespace:
	//self.single_chain_offset = namespace.chain_offset
	return ctx
}

// Dump dumps the context to the passed io.Writer.
func (ctx *Context) Dump(w io.Writer) {
	fmt.Printf("Context: %v\n", ctx)
}

// DataDir returns the data directory. Used to find files that don't have an absolute path.
func (ctx *Context) DataDir() string {
	return ctx.dataFilesDirectory
}

// IncludeDir returns the include directory. Used to include files that don't have an absolute path.
func (ctx *Context) IncludeDir() string {
	return ctx.includeFiles
}

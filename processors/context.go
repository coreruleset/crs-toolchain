// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package processors

import (
	"io"
	"os"

	"github.com/rs/zerolog/log"
)

var logger = log.With().Str("component", "processors").Logger()

type Context struct {
	rootDirectory      string
	rulesDirectory     string
	utilDirectory      string
	dataFilesDirectory string
	includeFiles       string
	singleRuleID       int
	singleChainOffset  bool
}

// NewContextForDir creates a new processor context
func NewContextForDir(rootDir string) *Context {
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

func NewContext() *Context {
	cwd, err := os.Getwd()
	if err != nil {
		panic("Failed to retrieve current working directory")
	}
	logger.Debug().Msgf("Resolved working directory: %s", cwd)

	return NewContextForDir(cwd)
}

func (ctx *Context) Dump(w io.Writer) {

}

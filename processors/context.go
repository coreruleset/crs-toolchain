// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package processors

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
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

// NewContextForDir creates a new processor context using the `rootDir` as the root directory.
func NewContextForDir(rootDir string) *Context {
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

// NewContext creates a new context using the current directory as base.
func NewContext() *Context {
	cwd, err := os.Getwd()
	if err != nil {
		panic("Failed to retrieve current working directory")
	}
	logger.Trace().Msgf("Resolved working directory: %s", cwd)

	root, err := findRootDirectory(cwd)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to find root directory")
	}
	logger.Debug().Msgf("Resolved root directory: %s", cwd)

	return NewContextForDir(root)
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

func findRootDirectory(startPath string) (string, error) {
	root := ""
	currentPath := startPath
	seen := make(map[string]bool)
	// root directory only will have a separator as the last rune
	for currentPath[len(currentPath)-1] != filepath.Separator {
		filepath.WalkDir(startPath, func(filePath string, dirEntry fs.DirEntry, err error) error {
			if seen[filePath] {
				// skip this directory
				return fs.SkipDir
			} else {
				seen[filePath] = true
			}

			// look for util/data/include
			if dirEntry != nil && dirEntry.IsDir() && dirEntry.Name() == "data" {
				_, err2 := os.Stat(path.Join(filePath, "include"))
				if err2 == nil {
					root = path.Dir(path.Dir(filePath))
					// stop processing
					return errors.New("done")
				} else {
					// skip this directory
					return fs.SkipDir
				}
			}
			// continue
			return nil
		})
		currentPath = path.Dir(currentPath)
	}
	if root == "" {
		return "", errors.New("failed to find root directory")
	}
	return root, nil
}

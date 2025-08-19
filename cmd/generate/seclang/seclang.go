// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package seclang

import (
	"errors"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	buildInternal "github.com/coreruleset/crs-toolchain/v2/cmd/generate/internal"
	"github.com/coreruleset/crs-toolchain/v2/internal/seclang"
)

var logger = log.With().Str("component", "cmd.generate.seclang").Logger()

func New(cmdContext *buildInternal.CommandContext) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "seclang [YAML_FILE]",
		Short: "Generate seclang files from CRSLang YAML files",
		Long: `Generate seclang files from CRSLang YAML files.
This command will parse CRSLang YAML files and generate corresponding seclang files
(.conf files) for use in ModSecurity configurations.

This is the reverse operation of the yaml and json generators, converting
from the structured CRSLang format back to the seclang format.

YAML_FILE is the path to the CRSLang YAML file to convert.
If not specified, the command will look for YAML files in the current directory.`,
		Args: cobra.MatchAll(cobra.MaximumNArgs(1), func(cmd *cobra.Command, args []string) error {
			allFlag := cmd.Flags().Lookup("all")
			if !allFlag.Changed && len(args) == 0 {
				return errors.New("expected either YAML_FILE or --all flag, found neither")
			} else if allFlag.Changed && len(args) > 0 {
				return errors.New("expected either YAML_FILE or --all flag, found both")
			}
			return nil
		}),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return nil
			}
			// Store the YAML file path for later use
			cmdContext.FileName = args[0]
			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			processAll, err := cmd.Flags().GetBool("all")
			if err != nil {
				logger.Fatal().Err(err).Msg("Failed to read value for 'all' flag")
			}
			performSeclangGeneration(processAll, cmdContext, cmd)
		},
	}

	buildFlags(cmd)
	return cmd
}

func buildFlags(cmd *cobra.Command) {
	cmd.Flags().BoolP("all", "a", false, `Instead of supplying a YAML_FILE, you can tell the script to
generate seclang for all YAML files in the current directory`)
}

func performSeclangGeneration(processAll bool, cmdContext *buildInternal.CommandContext, cmd *cobra.Command) {
	// Get output directory from parent command flags
	outputDir := cmdContext.GetOutputDir(cmd)

	// Create output directory if it doesn't exist
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		logger.Fatal().Err(err).Msg("Failed to create output directory")
	}

	if processAll {
		// Process all YAML files in the current directory
		err := filepath.WalkDir(".", func(filePath string, dirEntry fs.DirEntry, err error) error {
			if errors.Is(err, fs.ErrNotExist) {
				return err
			}

			if !dirEntry.IsDir() && path.Ext(dirEntry.Name()) == ".yaml" {
				processYamlFile(filePath, outputDir, cmdContext)
				return nil
			}
			return nil
		})
		if err != nil {
			logger.Fatal().Err(err).Msg("Failed to perform seclang generation")
		}
	} else {
		// Process the specified YAML file
		yamlFilePath := cmdContext.FileName
		if !path.IsAbs(yamlFilePath) {
			yamlFilePath = path.Join(".", yamlFilePath)
		}
		processYamlFile(yamlFilePath, outputDir, cmdContext)
	}
}

func processYamlFile(yamlFilePath string, outputDir string, cmdContext *buildInternal.CommandContext) {
	logger.Info().Msgf("Processing YAML file: %s", yamlFilePath)

	// Create seclang generator
	seclangGenerator := seclang.NewSeclangGenerator()

	// Generate seclang from YAML file
	seclangData, err := seclangGenerator.GenerateFile(yamlFilePath)
	if err != nil {
		logger.Error().Err(err).Msgf("Failed to generate seclang from YAML file %s", yamlFilePath)
		return
	}

	// Generate output filename based on input YAML file
	baseName := strings.TrimSuffix(path.Base(yamlFilePath), path.Ext(yamlFilePath))
	outputFile := path.Join(outputDir, baseName+".conf")

	// Write seclang file
	if err := os.WriteFile(outputFile, seclangData, 0644); err != nil {
		logger.Error().Err(err).Msgf("Failed to write seclang file %s", outputFile)
		return
	}

	logger.Info().Msgf("Generated seclang file: %s", outputFile)
}

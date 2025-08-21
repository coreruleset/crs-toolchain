// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package yaml

import (
	"errors"
	"os"
	"path"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	buildInternal "github.com/coreruleset/crs-toolchain/v2/cmd/generate/internal"
	"github.com/coreruleset/crs-toolchain/v2/internal/seclang"
)

var logger = log.With().Str("component", "cmd.build.yaml").Logger()

func New(cmdContext *buildInternal.CommandContext) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "yaml [RULE_ID]",
		Short: "Generate YAML files from seclang rules",
		Long: `Generate YAML files from seclang rules (.conf files).
This command will parse seclang rules and generate corresponding YAML files
for documentation or configuration purposes.

RULE_ID is the ID of the rule, e.g., 932100, or the rule file name.
If the rule is a chained rule, RULE_ID must be specified with the
offset of the chain from the chain starter rule. For example, to
generate a second level chained rule, RULE_ID would be 932100-chain2.`,
		Args: cobra.MatchAll(cobra.MaximumNArgs(1), func(cmd *cobra.Command, args []string) error {
			allFlag := cmd.Flags().Lookup("all")
			if !allFlag.Changed && len(args) == 0 {
				return errors.New("expected either RULE_ID or flag, found neither")
			} else if allFlag.Changed && len(args) > 0 {
				return errors.New("expected either RULE_ID or flag, found both")
			}
			return nil
		}),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return nil
			}
			err := buildInternal.ParseRuleId(args[0], cmdContext)
			if err != nil {
				cmd.PrintErrf("failed to parse the rule ID from the input '%s'\n", args[0])
				return err
			}

			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			processAll, err := cmd.Flags().GetBool("all")
			if err != nil {
				logger.Fatal().Err(err).Msg("Failed to read value for 'all' flag")
			}
			performYamlGeneration(processAll, cmdContext, cmd)
		},
	}

	buildFlags(cmd)
	return cmd
}

func buildFlags(cmd *cobra.Command) {
	cmd.Flags().BoolP("all", "a", false, `Instead of supplying a RULE_ID, you can tell the script to
generate YAML for all rules from their .conf files`)
}

func performYamlGeneration(processAll bool, cmdContext *buildInternal.CommandContext, cmd *cobra.Command) {
	// Get output directory from parent command flags
	outputDir := cmdContext.GetOutputDir(cmd)

	// Create output directory if it doesn't exist
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		logger.Fatal().Err(err).Msg("Failed to create output directory")
	}

	if processAll {
		// Generate comprehensive YAML for all rules in the directory
		yamlGenerator := seclang.NewYAMLGenerator()
		yamlData, err := yamlGenerator.GenerateFromDirectory(cmdContext.RootContext().RulesDir())
		if err != nil {
			logger.Fatal().Err(err).Msg("Failed to generate comprehensive YAML")
		}

		// Write to a single comprehensive YAML file
		outputFile := path.Join(outputDir, "crslang.yaml")
		if err := os.WriteFile(outputFile, yamlData, 0644); err != nil {
			logger.Fatal().Err(err).Msg("Failed to write comprehensive YAML file")
		}

		logger.Info().Msgf("Generated comprehensive YAML file: %s", outputFile)
	} else {
		ruleFilePath := path.Join(cmdContext.RootContext().RulesDir(), cmdContext.FileName)
		processRuleFile(ruleFilePath, outputDir, cmdContext)
	}
}

func processRuleFile(ruleFilePath string, outputDir string, cmdContext *buildInternal.CommandContext) {
	logger.Info().Msgf("Processing rule file: %s", ruleFilePath)

	// Create output directory if it doesn't exist
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		logger.Error().Err(err).Msgf("Failed to create output directory %s", outputDir)
		return
	}

	// Create YAML generator and generate comprehensive YAML for the file
	yamlGenerator := seclang.NewYAMLGenerator()
	yamlData, err := yamlGenerator.GenerateFile(ruleFilePath)
	if err != nil {
		logger.Error().Err(err).Msgf("Failed to generate YAML for %s", ruleFilePath)
		return
	}

	// Extract filename without extension for output filename
	fileName := path.Base(ruleFilePath)
	fileNameWithoutExt := strings.TrimSuffix(fileName, path.Ext(fileName))
	outputFile := path.Join(outputDir, fileNameWithoutExt+".yaml")

	// Write YAML data to file
	if err := os.WriteFile(outputFile, yamlData, 0644); err != nil {
		logger.Error().Err(err).Msgf("Failed to write YAML file %s", outputFile)
		return
	}

	logger.Info().Msgf("Generated YAML file: %s", outputFile)
}

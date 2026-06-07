// Copyright 2025 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package phpDictionaryGen

import (
	"fmt"
	"os"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/coreruleset/crs-toolchain/v2/cmd/internal"
	"github.com/coreruleset/crs-toolchain/v2/util"
)

var logger = log.With().Str("component", "cmd.util.php-dictionary-gen").Logger()

var (
	phpRepoPath       string
	frequencyLimit    int
	ageLimitDays      int
	frequencyListPath string
	rules             []string
)

// New creates the php-dictionary-gen cobra command.
func New(cmdContext *internal.CommandContext) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "php-dictionary-gen",
		Short: "Generate PHP function name data files",
		Long: `Generate *.data files for PHP function names used in CRS rules 933150, 933151, and 933161.

This command extracts function names from the PHP source code and filters them
into categories:

  1. English words (rule 933161): Function names that are valid English words,
     which are more likely to cause false positives and need a stricter match.

  2. Frequent functions (rule 933150): Non-English function names that appear
     frequently in PHP code on GitHub (above --frequency-limit occurrences).

  3. Rare functions (rule 933151): Non-English function names that are less
     common on GitHub (below --frequency-limit occurrences).

The command requires access to the GitHub API for frequency lookups.
Set the GITHUB_TOKEN environment variable to avoid rate limiting.

If --php-repo is not provided, the PHP source repository is cloned from
https://github.com/php/php-src (requires git to be available).`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Read GitHub token from env if not set via flag
			githubToken := os.Getenv("GITHUB_TOKEN")

			ctxt := cmdContext.RootContext()
			gen := util.NewPhpDictionaryGen()

			opts := util.PhpDictionaryGenOptions{
				PhpRepoPath:       phpRepoPath,
				FrequencyLimit:    frequencyLimit,
				AgeLimitDays:      ageLimitDays,
				FrequencyListPath: frequencyListPath,
				GitHubToken:       githubToken,
			}

			if len(rules) > 0 {
				opts.Rules = normalizeRules(rules)
				if err := validateRules(opts.Rules); err != nil {
					return err
				}
			}

			searcher := util.NewGitHubSearchClient(githubToken)

			logger.Info().Msg("Starting PHP dictionary generation")
			// wn is passed as nil; Generate will create it automatically when needed
			if err := gen.Generate(ctxt, opts, nil, searcher); err != nil {
				return fmt.Errorf("php-dictionary-gen failed: %w", err)
			}
			logger.Info().Msg("PHP dictionary generation complete")
			return nil
		},
	}

	buildFlags(cmd)
	return cmd
}

func buildFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&phpRepoPath, "php-repo", "p", "",
		"Path to a local PHP source repository. If not provided, the repository is cloned from GitHub.")
	cmd.Flags().IntVarP(&frequencyLimit, "frequency-limit", "F", util.DefaultFrequencyLimit,
		"Minimum number of GitHub occurrences to qualify for rule 933150. Functions below this threshold go to 933151.")
	cmd.Flags().IntVarP(&ageLimitDays, "age-limit", "a", util.DefaultAgeLimitDays,
		"Number of days before a frequency cache entry is considered stale and refreshed.")
	cmd.Flags().StringVarP(&frequencyListPath, "frequency-list", "f", "",
		"Path to the frequency cache file. If not provided, no caching is used.")
	cmd.Flags().StringSliceVarP(&rules, "rules", "r", []string{},
		`Comma-separated list of rules to generate. Available: 933150, 933151, 933161.
Default: all three rules.`)
}

func normalizeRules(input []string) []string {
	var result []string
	for _, r := range input {
		for _, part := range strings.Split(r, ",") {
			if trimmed := strings.TrimSpace(part); trimmed != "" {
				result = append(result, trimmed)
			}
		}
	}
	return result
}

func validateRules(rules []string) error {
	valid := map[string]struct{}{
		"933150": {},
		"933151": {},
		"933161": {},
	}
	for _, r := range rules {
		if _, ok := valid[r]; !ok {
			return fmt.Errorf("rule %s is not available; valid rules are: 933150, 933151, 933161", r)
		}
	}
	return nil
}

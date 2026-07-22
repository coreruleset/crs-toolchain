// Copyright 2025 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package phpFunctionNames

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/coreruleset/crs-toolchain/v2/cmd/internal"
	"github.com/coreruleset/crs-toolchain/v2/util"
)

var logger = log.With().Str("component", "cmd.generate.php-function-names").Logger()

var (
	phpRepoPath          string
	phpMajorVersionCount int
	frequencyLimit       int
	ageLimitDays         int
	frequencyListPath    string
	rules                []string
)

// New creates the php-function-names cobra command.
func New(cmdContext *internal.CommandContext) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "php-function-names",
		Short: "Generate PHP function name data files",
		Long: `Generate *.data and *.ra files for PHP function names used in CRS rules
933150, 933151, 933152, 933153, and 933161.

This command extracts function names from the PHP source code and filters them
into categories:

  1. English words (rule 933161): Function names that are valid English words,
     which are more likely to cause false positives and need a stricter match.

  2. Frequent functions (rule 933150): Non-English function names that appear
     frequently in PHP code on GitHub (above --frequency-limit occurrences).

  3. Rare functions (rules 933151/933152/933153): Non-English function names
     that are less common on GitHub (below --frequency-limit occurrences).
     Rule 933151 was split into three regex rules to work around regex size
     limitations; the word list is partitioned alphabetically (a-j, k-q, r-z)
     across 933151/933152/933153 respectively.

The command requires access to the GitHub API for frequency lookups.
Set the GITHUB_TOKEN (or GH_TOKEN) environment variable to avoid rate limiting.

If --php-repo is not provided, the PHP source repository is cloned from the
repository configured by php_dictionary_gen.php_repo_url in toolchain.yaml
(https://github.com/php/php-src by default; requires git to be available).
In that case, release branches from --php-major-version-count of its most
recent major versions are also scanned, so functions added only in older
major versions aren't missed. Within each major version considered, only its
oldest and newest release branch are scanned, not every minor release.

Defaults for the repository URL, frequency/age limits, major version count,
output file names, and GitHub rate-limit wait can all be set in
toolchain.yaml's php_dictionary_gen section; explicit flags always take
precedence.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Validate --php-repo path if provided
			if phpRepoPath != "" {
				info, err := os.Stat(phpRepoPath)
				if err != nil {
					return fmt.Errorf("--php-repo path does not exist: %s: %w", phpRepoPath, err)
				}
				if !info.IsDir() {
					return fmt.Errorf("--php-repo path is not a directory: %s", phpRepoPath)
				}
			}

			// Read the GitHub token; falls back to go-gh's own resolution when empty.
			githubToken := os.Getenv("GITHUB_TOKEN")
			if githubToken == "" {
				githubToken = os.Getenv("GH_TOKEN")
			}

			ctxt := cmdContext.RootContext()
			cfg := ctxt.Configuration().PhpDictionaryGen
			gen := util.NewPhpDictionaryGen()

			opts := util.PhpDictionaryGenOptions{
				PhpRepoPath:        phpRepoPath,
				PhpRepoURL:         cfg.PhpRepoURL,
				FrequencyListPath:  frequencyListPath,
				Rule933150FileName: cfg.Rule933150FileName,
				Rule933151FileName: cfg.Rule933151FileName,
				Rule933152FileName: cfg.Rule933152FileName,
				Rule933153FileName: cfg.Rule933153FileName,
				Rule933161FileName: cfg.Rule933161FileName,
				MaxRateLimitWait:   time.Duration(cfg.MaxRateLimitWaitSeconds) * time.Second,
			}

			opts.FrequencyLimit = frequencyLimit
			if !cmd.Flags().Changed("frequency-limit") {
				opts.FrequencyLimit = cfg.FrequencyLimit
			}
			opts.AgeLimitDays = ageLimitDays
			if !cmd.Flags().Changed("age-limit") {
				opts.AgeLimitDays = cfg.AgeLimitDays
			}
			opts.PhpMajorVersionCount = phpMajorVersionCount
			if !cmd.Flags().Changed("php-major-version-count") {
				opts.PhpMajorVersionCount = cfg.PhpMajorVersionCount
			}

			if len(rules) > 0 {
				opts.Rules = normalizeRules(rules)
				if err := validateRules(opts.Rules); err != nil {
					return err
				}
			}

			searcher, err := util.NewGitHubSearchClient(githubToken)
			if err != nil {
				return fmt.Errorf("creating GitHub search client: %w", err)
			}

			logger.Info().Msg("Starting PHP dictionary generation")
			// wn is passed as nil; Generate will create it automatically when needed
			if err := gen.Generate(cmd.Context(), ctxt, opts, nil, searcher); err != nil {
				return fmt.Errorf("php-function-names failed: %w", err)
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
	cmd.Flags().IntVarP(&phpMajorVersionCount, "php-major-version-count", "R", util.DefaultPhpMajorVersionCount,
		`Number of most recent PHP major versions (besides the default branch) to also extract function names from.
Only the oldest and newest release branch of each major version considered are scanned. Only applies when --php-repo is not provided.`)
	cmd.Flags().IntVarP(&frequencyLimit, "frequency-limit", "F", util.DefaultFrequencyLimit,
		"Minimum number of GitHub occurrences to qualify for rule 933150. Functions below this threshold go to 933151/933152/933153.")
	cmd.Flags().IntVarP(&ageLimitDays, "age-limit", "a", util.DefaultAgeLimitDays,
		"Number of days before a frequency cache entry is considered stale and refreshed.")
	cmd.Flags().StringVarP(&frequencyListPath, "frequency-list", "L", "",
		"Path to the frequency cache file. If not provided, no caching is used.")
	cmd.Flags().StringSliceVarP(&rules, "rules", "r", []string{},
		`Comma-separated list of rules to generate. Available: 933150, 933151, 933152, 933153, 933161.
Default: all five rules.`)
}

func normalizeRules(input []string) []string {
	var result []string
	for _, r := range input {
		if trimmed := strings.TrimSpace(r); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func validateRules(rules []string) error {
	valid := map[string]struct{}{
		"933150": {},
		"933151": {},
		"933152": {},
		"933153": {},
		"933161": {},
	}
	for _, r := range rules {
		if _, ok := valid[r]; !ok {
			return fmt.Errorf("rule %s is not available; valid rules are: 933150, 933151, 933152, 933153, 933161", r)
		}
	}
	return nil
}

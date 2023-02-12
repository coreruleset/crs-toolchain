// Copyright 2023 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package updater

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"

	"github.com/creativeprojects/go-selfupdate"
	"github.com/rs/zerolog/log"
)

var logger = log.With().Str("component", "updater").Logger()

// Updater checks the latest version in GitHub and self-updates if there is a newer release.
func Updater(version string) error {
	if version == "dev" {
		logger.Info().Msgf("You are using a development version. Canceling update.")
		return nil
	}
	source, err := selfupdate.NewGitHubSource(selfupdate.GitHubConfig{})
	if err != nil {
		logger.Fatal().Err(err)
	}
	updater, err := selfupdate.NewUpdater(selfupdate.Config{
		Source:    source,
		Validator: &selfupdate.ChecksumValidator{UniqueFilename: "crs-toolchain-checksums.txt"}, // checksum from goreleaser
	})
	if err != nil {
		return err
	}
	latest, found, err := updater.DetectLatest(context.Background(), selfupdate.ParseSlug("coreruleset/crs-toolchain"))
	if err != nil {
		return fmt.Errorf("error occurred while detecting version: %w", err)
	}
	if !found {
		return fmt.Errorf("latest version for %s/%s could not be found from github repository", runtime.GOOS, runtime.GOARCH)
	}

	logger.Info().Msgf("Version is (%s).", version)
	if latest.LessOrEqual(version) {
		logger.Info().Msgf("Current version (%s) is the latest", version)
		return nil
	}

	exe, err := os.Executable()
	if err != nil {
		return errors.New("could not locate executable path")
	}
	if err := selfupdate.UpdateTo(context.Background(), latest.AssetURL, latest.AssetName, exe); err != nil {
		return fmt.Errorf("error occurred while updating binary: %w", err)
	}
	logger.Info().Msgf("Successfully updated to version %s", latest.Version())
	return nil
}

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
// returns the version string of the updated release, or an error if something went wrong.
func Updater(version string, executablePath string) (string, error) {
	emptyVersion := ""
	if version == "dev" {
		logger.Info().Msgf("You are using a development version. Cancelling update.")
		return emptyVersion, nil
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
		return emptyVersion, err
	}
	latest, found, err := updater.DetectLatest(context.Background(), selfupdate.ParseSlug("coreruleset/crs-toolchain"))
	if err != nil {
		return emptyVersion, fmt.Errorf("error occurred while detecting version: %w", err)
	}
	if !found {
		return emptyVersion, fmt.Errorf("latest version for %s/%s could not be found in github repository", runtime.GOOS, runtime.GOARCH)
	}

	logger.Info().Msgf("Your version is %s.", version)
	if latest.LessOrEqual(version) {
		logger.Info().Msgf("You have the latest version installed.", version)
		return version, nil
	}

	// passing executablePath allows to test the updater without actually updating the binary
	if executablePath == "" {
		exe, err := os.Executable()
		if err != nil {
			return emptyVersion, errors.New("could not locate executable path")
		}
		executablePath = exe
		logger.Info().Msgf("Updating file \"%s\"", executablePath)
	}

	if err := selfupdate.UpdateTo(context.Background(), latest.AssetURL, latest.AssetName, executablePath); err != nil {
		return emptyVersion, fmt.Errorf("error occurred while updating binary: %w", err)
	}
	logger.Info().Msgf("Successfully updated to version %s", latest.Version())
	return latest.Version(), nil
}

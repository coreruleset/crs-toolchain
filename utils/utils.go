// Copyright 2024 OWASP ModSecurity Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/hashicorp/go-getter/v2"
)

func IsEscaped(input string, position int) bool {
	escapeCounter := 0
	for backtrackIndex := position - 1; backtrackIndex >= 0; backtrackIndex-- {
		if input[backtrackIndex] != '\\' {
			break
		}
		escapeCounter++
	}
	return escapeCounter%2 != 0
}

func DownloadFile(filepath, url string) error {
	request := &getter.Request{
		Src:     url,
		Dst:     filepath,
		GetMode: getter.ModeAny,
	}
	client := &getter.Client{
		Getters: []getter.Getter{
			new(getter.HttpGetter),
		},
	}

	_, err := client.Get(context.Background(), request)
	return err
}

func GetCacheFilePath(fileName string) (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	crsToolchainDir := filepath.Join(homeDir, ".crs-toolchain")

	// Create ~/.crs-toolchain folder if it doesn't exist
	if _, err := os.Stat(crsToolchainDir); os.IsNotExist(err) {
		if err := os.MkdirAll(crsToolchainDir, 0755); err != nil {
			return "", err
		}
	}

	return filepath.Join(crsToolchainDir, fileName), nil
}

func RunGit(repositoryPath string, args ...string) ([]byte, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = repositoryPath
	return cmd.CombinedOutput()
}

// githubAPIBaseURL is overridable in tests to point GetLatestGitHubRelease at
// an httptest server instead of the real GitHub API.
var githubAPIBaseURL = "https://api.github.com"

// GetLatestGitHubRelease fetches the latest release of owner/repo from the
// GitHub API and returns the release tag, the name, and the
// browser_download_url of the first asset whose name satisfies matchAsset.
//
// The asset name is returned in addition to the tag because releases can
// gain, lose, or rename assets after being published without the tag
// changing; callers that cache the downloaded asset should key their cache
// on the asset name (or download URL), not on the tag alone, or they risk
// silently reusing a stale, differently-formatted asset cached under an
// older matching name.
func GetLatestGitHubRelease(owner, repo string, matchAsset func(name string) bool) (tag, assetName, downloadURL string, err error) {
	apiURL := fmt.Sprintf("%s/repos/%s/%s/releases/latest", githubAPIBaseURL, owner, repo)
	resp, err := http.Get(apiURL) //nolint:noctx
	if err != nil {
		return "", "", "", err
	}
	defer resp.Body.Close()

	var release struct {
		TagName string `json:"tag_name"`
		Assets  []struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", "", "", err
	}
	for _, asset := range release.Assets {
		if matchAsset(asset.Name) {
			return release.TagName, asset.Name, asset.BrowserDownloadURL, nil
		}
	}
	return "", "", "", fmt.Errorf("no matching asset found in release %s", release.TagName)
}

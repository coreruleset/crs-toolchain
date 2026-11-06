// Copyright 2026 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package plugin

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"time"

	"github.com/cli/go-gh/v2/pkg/api"
)

// githubAPIBaseURL is a var so tests can point it at an httptest server. It
// is passed as an absolute URL to the go-gh REST client, which uses it
// as-is instead of resolving it against the client's configured host.
var githubAPIBaseURL = "https://api.github.com"

// githubTimeout bounds a single GitHub API or download request.
var githubTimeout = 60 * time.Second

// maxTarballBytes bounds the size of a downloaded plugin source tarball.
// Plugin repositories are a handful of rule/config/lua files; anything
// approaching this size indicates a misbehaving or malicious release rather
// than a legitimate plugin.
const maxTarballBytes = 100 << 20 // 100 MiB

var repositoryURLPattern = regexp.MustCompile(`^https://github\.com/([^/]+)/([^/]+?)/?$`)

// parseRepository extracts the owner and repo name from a GitHub repository
// URL, as published in the registry's `repository` field.
func parseRepository(repositoryURL string) (owner, repo string, err error) {
	matches := repositoryURLPattern.FindStringSubmatch(repositoryURL)
	if matches == nil {
		return "", "", fmt.Errorf("%q is not a GitHub repository URL", repositoryURL)
	}
	return matches[1], matches[2], nil
}

// newGitHubClient builds a go-gh REST client. If a GH_TOKEN or GITHUB_TOKEN
// is set, or the gh CLI is configured, requests are authenticated, which is
// what allows installing from a private plugin repository.
func newGitHubClient() (*api.RESTClient, error) {
	client, err := api.NewRESTClient(api.ClientOptions{
		Headers: map[string]string{
			"Accept":               "application/vnd.github+json",
			"X-GitHub-Api-Version": "2022-11-28",
		},
		Timeout: githubTimeout,
	})
	if err != nil {
		return nil, fmt.Errorf("creating GitHub client: %w", err)
	}
	return client, nil
}

// resolveTag resolves version to a concrete GitHub release tag. An empty
// version resolves to the newest release. A repository with no releases, or
// a pinned version that isn't a published release, is a clear error rather
// than falling back to a branch.
func resolveTag(ctx context.Context, client *api.RESTClient, owner, repo, version string) (string, error) {
	path := fmt.Sprintf("%s/repos/%s/%s/releases/latest", githubAPIBaseURL, owner, repo)
	if version != "" {
		path = fmt.Sprintf("%s/repos/%s/%s/releases/tags/%s", githubAPIBaseURL, owner, repo, version)
	}

	var release struct {
		TagName string `json:"tag_name"`
	}
	if err := client.DoWithContext(ctx, http.MethodGet, path, nil, &release); err != nil {
		var httpErr *api.HTTPError
		if errors.As(err, &httpErr) && httpErr.StatusCode == http.StatusNotFound {
			if version != "" {
				return "", fmt.Errorf("no release tagged %q found for %s/%s", version, owner, repo)
			}
			return "", fmt.Errorf("no releases found for %s/%s (repository may be private or have no releases)", owner, repo)
		}
		return "", fmt.Errorf("resolving release for %s/%s: %w", owner, repo, err)
	}
	return release.TagName, nil
}

// downloadTarball downloads the source archive for owner/repo at tag into
// destFile. GitHub plugin releases publish no release assets, so the source
// tarball is the only artifact that can be fetched at a given tag.
func downloadTarball(ctx context.Context, client *api.RESTClient, owner, repo, tag, destFile string) error {
	ctx, cancel := context.WithTimeout(ctx, githubTimeout)
	defer cancel()

	path := fmt.Sprintf("%s/repos/%s/%s/tarball/%s", githubAPIBaseURL, owner, repo, tag)
	resp, err := client.RequestWithContext(ctx, http.MethodGet, path, nil)
	if err != nil {
		return fmt.Errorf("downloading %s/%s@%s: %w", owner, repo, tag, err)
	}
	defer resp.Body.Close()

	out, err := os.Create(destFile)
	if err != nil {
		return fmt.Errorf("creating %s for %s/%s@%s: %w", destFile, owner, repo, tag, err)
	}

	written, copyErr := io.Copy(out, io.LimitReader(resp.Body, maxTarballBytes+1))
	closeErr := out.Close()
	if err := errors.Join(copyErr, closeErr); err != nil {
		return fmt.Errorf("writing %s/%s@%s: %w", owner, repo, tag, err)
	}
	if written > maxTarballBytes {
		return fmt.Errorf("downloading %s/%s@%s: archive exceeds maximum size of %d bytes", owner, repo, tag, maxTarballBytes)
	}
	return nil
}

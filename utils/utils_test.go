// Copyright 2024 OWASP ModSecurity Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

type utilsTestSuite struct {
	suite.Suite
}

func TestRunUtilsTestSuite(t *testing.T) {
	suite.Run(t, new(utilsTestSuite))
}

func (s *utilsTestSuite) TestIsEscaped() {
	s.True(IsEscaped(`abc\(de`, 4))
	s.True(IsEscaped(`\(abc`, 1))
	s.True(IsEscaped(`abc\(`, 4))
}

func (s *utilsTestSuite) TestIsEscaped_Backslashes() {
	s.True(IsEscaped(`abc\\de`, 4))
	s.True(IsEscaped(`\\abc`, 1))
	s.True(IsEscaped(`abc\\`, 4))
}

func (s *utilsTestSuite) TestIsEscaped_Not() {
	s.False(IsEscaped(`abc\\(de`, 5))
	s.False(IsEscaped(`\\(abc`, 2))
	s.False(IsEscaped(`abc\\(`, 5))
}

func (s *utilsTestSuite) TestIsEscaped_Not_Backslashes() {
	s.False(IsEscaped(`abc\\\de`, 5))
	s.False(IsEscaped(`\\\abc`, 2))
	s.False(IsEscaped(`abc\\\`, 5))
}

// stubGitHubAPI starts an httptest server serving body for
// /repos/{owner}/{repo}/releases/latest, points githubAPIBaseURL at it, and
// returns a cleanup func that restores the original base URL and closes the
// server.
func (s *utilsTestSuite) stubGitHubAPI(status int, body string) func() {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))

	original := githubAPIBaseURL
	githubAPIBaseURL = server.URL

	return func() {
		githubAPIBaseURL = original
		server.Close()
	}
}

func (s *utilsTestSuite) TestGetLatestGitHubRelease_SingleMatchingAsset() {
	defer s.stubGitHubAPI(http.StatusOK, `{
		"tag_name": "v1.2.3",
		"assets": [
			{"name": "release.zip", "browser_download_url": "https://example.com/release.zip"}
		]
	}`)()

	tag, assetName, downloadURL, err := GetLatestGitHubRelease("owner", "repo", func(name string) bool {
		return name == "release.zip"
	})

	s.NoError(err)
	s.Equal("v1.2.3", tag)
	s.Equal("release.zip", assetName)
	s.Equal("https://example.com/release.zip", downloadURL)
}

func (s *utilsTestSuite) TestGetLatestGitHubRelease_PicksFirstMatchingAsset() {
	// Regression test: when multiple assets satisfy matchAsset, the first one
	// in array order must win. A release can gain a new matching asset over
	// time without changing its tag, so callers rely on array order being
	// stable and on "first match" being well-defined behavior.
	defer s.stubGitHubAPI(http.StatusOK, `{
		"tag_name": "v1.2.3",
		"assets": [
			{"name": "first-match.zip", "browser_download_url": "https://example.com/first-match.zip"},
			{"name": "second-match.zip", "browser_download_url": "https://example.com/second-match.zip"}
		]
	}`)()

	tag, assetName, downloadURL, err := GetLatestGitHubRelease("owner", "repo", func(name string) bool {
		return name == "first-match.zip" || name == "second-match.zip"
	})

	s.NoError(err)
	s.Equal("v1.2.3", tag)
	s.Equal("first-match.zip", assetName)
	s.Equal("https://example.com/first-match.zip", downloadURL)
}

func (s *utilsTestSuite) TestGetLatestGitHubRelease_SkipsNonMatchingAssets() {
	defer s.stubGitHubAPI(http.StatusOK, `{
		"tag_name": "v1.2.3",
		"assets": [
			{"name": "unrelated.txt", "browser_download_url": "https://example.com/unrelated.txt"},
			{"name": "wanted.zip", "browser_download_url": "https://example.com/wanted.zip"}
		]
	}`)()

	tag, assetName, downloadURL, err := GetLatestGitHubRelease("owner", "repo", func(name string) bool {
		return name == "wanted.zip"
	})

	s.NoError(err)
	s.Equal("v1.2.3", tag)
	s.Equal("wanted.zip", assetName)
	s.Equal("https://example.com/wanted.zip", downloadURL)
}

func (s *utilsTestSuite) TestGetLatestGitHubRelease_NoMatchingAsset() {
	defer s.stubGitHubAPI(http.StatusOK, `{
		"tag_name": "v1.2.3",
		"assets": [
			{"name": "unrelated.txt", "browser_download_url": "https://example.com/unrelated.txt"}
		]
	}`)()

	_, _, _, err := GetLatestGitHubRelease("owner", "repo", func(name string) bool {
		return name == "wanted.zip"
	})

	s.ErrorContains(err, "no matching asset found in release v1.2.3")
}

func (s *utilsTestSuite) TestGetLatestGitHubRelease_NoAssets() {
	defer s.stubGitHubAPI(http.StatusOK, `{"tag_name": "v1.2.3", "assets": []}`)()

	_, _, _, err := GetLatestGitHubRelease("owner", "repo", func(name string) bool {
		return true
	})

	s.ErrorContains(err, "no matching asset found in release v1.2.3")
}

func (s *utilsTestSuite) TestGetLatestGitHubRelease_MalformedJSON() {
	defer s.stubGitHubAPI(http.StatusOK, `not json`)()

	_, _, _, err := GetLatestGitHubRelease("owner", "repo", func(name string) bool {
		return true
	})

	s.Error(err)
}

func (s *utilsTestSuite) TestGetLatestGitHubRelease_RequestFailure() {
	original := githubAPIBaseURL
	githubAPIBaseURL = "http://127.0.0.1:0"
	defer func() { githubAPIBaseURL = original }()

	_, _, _, err := GetLatestGitHubRelease("owner", "repo", func(name string) bool {
		return true
	})

	s.Error(err)
}

func (s *utilsTestSuite) TestGetLatestGitHubRelease_NonSuccessStatus() {
	defer s.stubGitHubAPI(http.StatusInternalServerError, `{"message": "boom"}`)()

	_, _, _, err := GetLatestGitHubRelease("owner", "repo", func(name string) bool {
		return true
	})

	s.ErrorContains(err, "500")
}

func (s *utilsTestSuite) TestGetLatestGitHubRelease_Timeout() {
	// Server that never responds until the test releases it, forcing the
	// request to exceed the configured timeout.
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	defer server.Close()
	defer close(release)

	originalURL := githubAPIBaseURL
	githubAPIBaseURL = server.URL
	defer func() { githubAPIBaseURL = originalURL }()

	originalTimeout := githubAPITimeout
	githubAPITimeout = 50 * time.Millisecond
	defer func() { githubAPITimeout = originalTimeout }()

	_, _, _, err := GetLatestGitHubRelease("owner", "repo", func(name string) bool {
		return true
	})

	s.Error(err)
}

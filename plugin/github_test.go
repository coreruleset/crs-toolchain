// Copyright 2026 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package plugin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/cli/go-gh/v2/pkg/api"
	"github.com/stretchr/testify/suite"
)

type githubTestSuite struct {
	suite.Suite
	client *api.RESTClient
}

func TestRunGitHubTestSuite(t *testing.T) {
	suite.Run(t, new(githubTestSuite))
}

func (s *githubTestSuite) SetupTest() {
	client, err := api.NewRESTClient(api.ClientOptions{})
	s.Require().NoError(err)
	s.client = client
}

func (s *githubTestSuite) stubGitHubAPI(handler http.HandlerFunc) func() {
	server := httptest.NewServer(handler)
	original := githubAPIBaseURL
	githubAPIBaseURL = server.URL
	return func() {
		githubAPIBaseURL = original
		server.Close()
	}
}

func (s *githubTestSuite) TestParseRepository_Valid() {
	owner, repo, err := parseRepository("https://github.com/coreruleset/fake-bot-plugin")

	s.Require().NoError(err)
	s.Equal("coreruleset", owner)
	s.Equal("fake-bot-plugin", repo)
}

func (s *githubTestSuite) TestParseRepository_TrailingSlash() {
	owner, repo, err := parseRepository("https://github.com/coreruleset/fake-bot-plugin/")

	s.Require().NoError(err)
	s.Equal("coreruleset", owner)
	s.Equal("fake-bot-plugin", repo)
}

func (s *githubTestSuite) TestParseRepository_NotGitHub() {
	_, _, err := parseRepository("https://gitlab.com/coreruleset/fake-bot-plugin")

	s.Require().Error(err)
}

func (s *githubTestSuite) TestResolveTag_Latest() {
	defer s.stubGitHubAPI(func(w http.ResponseWriter, r *http.Request) {
		s.Equal("/repos/owner/repo/releases/latest", r.URL.Path)
		_, _ = w.Write([]byte(`{"tag_name": "v1.1.0"}`))
	})()

	tag, err := resolveTag(context.Background(), s.client, "owner", "repo", "")

	s.Require().NoError(err)
	s.Equal("v1.1.0", tag)
}

func (s *githubTestSuite) TestResolveTag_Pinned() {
	defer s.stubGitHubAPI(func(w http.ResponseWriter, r *http.Request) {
		s.Equal("/repos/owner/repo/releases/tags/v1.0.0", r.URL.Path)
		_, _ = w.Write([]byte(`{"tag_name": "v1.0.0"}`))
	})()

	tag, err := resolveTag(context.Background(), s.client, "owner", "repo", "v1.0.0")

	s.Require().NoError(err)
	s.Equal("v1.0.0", tag)
}

func (s *githubTestSuite) TestResolveTag_NoReleases() {
	defer s.stubGitHubAPI(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message": "Not Found"}`))
	})()

	_, err := resolveTag(context.Background(), s.client, "owner", "repo", "")

	s.Require().Error(err)
	s.Contains(err.Error(), "no releases found")
}

func (s *githubTestSuite) TestResolveTag_UnknownPinnedVersion() {
	defer s.stubGitHubAPI(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message": "Not Found"}`))
	})()

	_, err := resolveTag(context.Background(), s.client, "owner", "repo", "v9.9.9")

	s.Require().Error(err)
	s.Contains(err.Error(), `no release tagged "v9.9.9"`)
}

func (s *githubTestSuite) TestDownloadTarball() {
	defer s.stubGitHubAPI(func(w http.ResponseWriter, r *http.Request) {
		s.Equal("/repos/owner/repo/tarball/v1.0.0", r.URL.Path)
		_, _ = w.Write([]byte("fake tarball bytes"))
	})()

	destFile := filepath.Join(s.T().TempDir(), "plugin.tar.gz")
	err := downloadTarball(context.Background(), s.client, "owner", "repo", "v1.0.0", destFile)

	s.Require().NoError(err)
	content, err := os.ReadFile(destFile)
	s.Require().NoError(err)
	s.Equal("fake tarball bytes", string(content))
}

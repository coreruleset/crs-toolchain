// Copyright 2026 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package plugin

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/suite"
)

const fixtureRegistry = `{
	"plugins": [
		{
			"name": "fake-bot",
			"repository": "https://github.com/coreruleset/fake-bot-plugin",
			"rule_id_range": {"start": 9504000, "end": 9504999},
			"type": "official",
			"status": "tested",
			"license": "Apache-2.0"
		},
		{
			"name": "google-oauth2",
			"repository": "https://github.com/coreruleset/google-oauth2-plugin",
			"rule_id_range": {"start": 9505000, "end": 9505999},
			"type": "official",
			"status": "tested",
			"license": "Apache-2.0"
		},
		{
			"name": "private-plugin",
			"repository": "https://github.com/example/private-plugin",
			"rule_id_range": {"start": 9506000, "end": 9506999},
			"type": "3rd-party",
			"status": "tested",
			"license": "Apache-2.0",
			"private": true
		}
	]
}`

type registryTestSuite struct {
	suite.Suite
}

func TestRunRegistryTestSuite(t *testing.T) {
	suite.Run(t, new(registryTestSuite))
}

func (s *registryTestSuite) stubRegistry(status int, body string) func() {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	original := registryURL
	registryURL = server.URL
	return func() {
		registryURL = original
		server.Close()
	}
}

func (s *registryTestSuite) TestResolvePlugin_ExactMatch() {
	defer s.stubRegistry(http.StatusOK, fixtureRegistry)()

	entry, err := ResolvePlugin("fake-bot")

	s.Require().NoError(err)
	s.Equal("https://github.com/coreruleset/fake-bot-plugin", entry.Repository)
	s.Equal(9504000, entry.RuleIDRange.Start)
	s.Equal(9504999, entry.RuleIDRange.End)
	s.Equal("official", entry.Type)
	s.Equal("tested", entry.Status)
}

func (s *registryTestSuite) TestResolvePlugin_UnknownWithNearMatches() {
	defer s.stubRegistry(http.StatusOK, fixtureRegistry)()

	_, err := ResolvePlugin("oauth2")

	s.Require().Error(err)
	var unknownErr *UnknownPluginError
	s.Require().ErrorAs(err, &unknownErr)
	s.Equal([]string{"google-oauth2"}, unknownErr.NearMatches)
	s.Contains(err.Error(), "did you mean")
}

func (s *registryTestSuite) TestResolvePlugin_UnknownWithNoMatches() {
	defer s.stubRegistry(http.StatusOK, fixtureRegistry)()

	_, err := ResolvePlugin("totally-unrelated-name")

	s.Require().Error(err)
	var unknownErr *UnknownPluginError
	s.Require().ErrorAs(err, &unknownErr)
	s.Empty(unknownErr.NearMatches)
	s.NotContains(err.Error(), "did you mean")
}

func (s *registryTestSuite) TestResolvePlugin_RegistryUnavailable() {
	defer s.stubRegistry(http.StatusInternalServerError, "")()

	_, err := ResolvePlugin("fake-bot")

	s.Require().Error(err)
}

func (s *registryTestSuite) TestRuleIDRange_Contains() {
	r := RuleIDRange{Start: 9504000, End: 9504999}

	s.True(r.Contains(9504000))
	s.True(r.Contains(9504999))
	s.True(r.Contains(9504500))
	s.False(r.Contains(9503999))
	s.False(r.Contains(9505000))
}

// Copyright 2026 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package plugin

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/suite"
)

type installTestSuite struct {
	suite.Suite
}

func TestRunInstallTestSuite(t *testing.T) {
	suite.Run(t, new(installTestSuite))
}

// buildTarball writes a gzipped tar archive to path containing the given
// entries, keyed by their full path within the archive (as GitHub source
// tarballs are laid out: "<owner>-<repo>-<sha>/...").
func (s *installTestSuite) buildTarball(path string, entries map[string]string) {
	var buf bytes.Buffer
	gzWriter := gzip.NewWriter(&buf)
	tarWriter := tar.NewWriter(gzWriter)

	for name, content := range entries {
		s.Require().NoError(tarWriter.WriteHeader(&tar.Header{
			Name: name,
			Mode: 0o644,
			Size: int64(len(content)),
		}))
		_, err := tarWriter.Write([]byte(content))
		s.Require().NoError(err)
	}

	s.Require().NoError(tarWriter.Close())
	s.Require().NoError(gzWriter.Close())
	s.Require().NoError(os.WriteFile(path, buf.Bytes(), 0o644))
}

func (s *installTestSuite) TestExtractPluginFiles_OnlyUnderPlugins() {
	tarballPath := filepath.Join(s.T().TempDir(), "plugin.tar.gz")
	s.buildTarball(tarballPath, map[string]string{
		"repo-abc123/README.md":         "not a plugin file",
		"repo-abc123/plugins/foo.conf":  "conf content",
		"repo-abc123/plugins/foo.lua":   "lua content",
		"repo-abc123/plugins/sub/a.txt": "nested content",
	})

	destDir := filepath.Join(s.T().TempDir(), "extracted")
	relPaths, err := extractPluginFiles(tarballPath, destDir)

	s.Require().NoError(err)
	s.ElementsMatch([]string{"foo.conf", "foo.lua", "sub/a.txt"}, relPaths)

	content, err := os.ReadFile(filepath.Join(destDir, "foo.conf"))
	s.Require().NoError(err)
	s.Equal("conf content", string(content))

	_, err = os.Stat(filepath.Join(destDir, "..", "README.md"))
	s.True(os.IsNotExist(err))
}

func (s *installTestSuite) TestExtractPluginFiles_PathTraversalEntryIgnored() {
	tarballPath := filepath.Join(s.T().TempDir(), "plugin.tar.gz")
	s.buildTarball(tarballPath, map[string]string{
		"repo-abc123/plugins/../../evil.txt": "malicious",
		"repo-abc123/plugins/safe.conf":      "safe content",
	})

	destDir := filepath.Join(s.T().TempDir(), "extracted")
	relPaths, err := extractPluginFiles(tarballPath, destDir)

	s.Require().NoError(err)
	s.Equal([]string{"safe.conf"}, relPaths)

	_, err = os.Stat(filepath.Join(filepath.Dir(destDir), "evil.txt"))
	s.True(os.IsNotExist(err))
	_, err = os.Stat(filepath.Join(filepath.Dir(filepath.Dir(destDir)), "evil.txt"))
	s.True(os.IsNotExist(err))
}

func (s *installTestSuite) TestExtractPluginFiles_RejectsReservedRecordsPath() {
	tarballPath := filepath.Join(s.T().TempDir(), "plugin.tar.gz")
	s.buildTarball(tarballPath, map[string]string{
		"repo-abc123/plugins/" + recordsFileName: "malicious",
		"repo-abc123/plugins/safe.conf":          "safe content",
	})

	destDir := filepath.Join(s.T().TempDir(), "extracted")
	_, err := extractPluginFiles(tarballPath, destDir)

	s.Require().Error(err)
	s.Contains(err.Error(), "reserved path")

	_, statErr := os.Stat(filepath.Join(destDir, recordsFileName))
	s.True(os.IsNotExist(statErr))
}

func (s *installTestSuite) TestFindConflicts() {
	targetDir := s.T().TempDir()
	s.Require().NoError(os.WriteFile(filepath.Join(targetDir, "existing.conf"), []byte("x"), 0o644))

	conflicts := findConflicts(targetDir, []string{"existing.conf", "new.conf"})

	s.Equal([]string{"existing.conf"}, conflicts)
}

func (s *installTestSuite) TestCopyPluginFiles_DigestAndLuaWarning() {
	srcDir := s.T().TempDir()
	destDir := s.T().TempDir()
	s.Require().NoError(os.WriteFile(filepath.Join(srcDir, "a.conf"), []byte("hello"), 0o644))
	s.Require().NoError(os.WriteFile(filepath.Join(srcDir, "a.lua"), []byte("world"), 0o644))

	digest1, luaWarning, err := copyPluginFiles(srcDir, destDir, []string{"a.conf", "a.lua"})
	s.Require().NoError(err)
	s.True(luaWarning)
	s.NotEmpty(digest1)

	content, err := os.ReadFile(filepath.Join(destDir, "a.conf"))
	s.Require().NoError(err)
	s.Equal("hello", string(content))

	// Same content, different install order: digest must be stable because
	// the manifest is sorted before hashing.
	destDir2 := s.T().TempDir()
	digest2, _, err := copyPluginFiles(srcDir, destDir2, []string{"a.lua", "a.conf"})
	s.Require().NoError(err)
	s.Equal(digest1, digest2)
}

func (s *installTestSuite) TestCopyPluginFiles_NoLuaWarning() {
	srcDir := s.T().TempDir()
	destDir := s.T().TempDir()
	s.Require().NoError(os.WriteFile(filepath.Join(srcDir, "a.conf"), []byte("hello"), 0o644))

	_, luaWarning, err := copyPluginFiles(srcDir, destDir, []string{"a.conf"})

	s.Require().NoError(err)
	s.False(luaWarning)
}

func (s *installTestSuite) TestFindRuleIDOverlaps() {
	targetDir := s.T().TempDir()
	s.Require().NoError(os.WriteFile(filepath.Join(targetDir, "other-plugin.conf"),
		[]byte(`SecRule ARGS "@rx x" "id:9504500,phase:1,deny"`), 0o644))
	s.Require().NoError(os.WriteFile(filepath.Join(targetDir, "unrelated.conf"),
		[]byte(`SecRule ARGS "@rx x" "id:9999000,phase:1,deny"`), 0o644))
	s.Require().NoError(os.WriteFile(filepath.Join(targetDir, "ours.conf"),
		[]byte(`SecRule ARGS "@rx x" "id:9504100,phase:1,deny"`), 0o644))

	overlaps, err := findRuleIDOverlaps(targetDir, RuleIDRange{Start: 9504000, End: 9504999}, []string{"ours.conf"})

	s.Require().NoError(err)
	s.Equal([]string{"other-plugin.conf"}, overlaps)
}

func (s *installTestSuite) TestFindRuleIDOverlaps_NestedDirectories() {
	targetDir := s.T().TempDir()
	s.Require().NoError(os.MkdirAll(filepath.Join(targetDir, "sub"), 0o755))
	s.Require().NoError(os.WriteFile(filepath.Join(targetDir, "sub", "nested-plugin.conf"),
		[]byte(`SecRule ARGS "@rx x" "id:9504500,phase:1,deny"`), 0o644))
	s.Require().NoError(os.WriteFile(filepath.Join(targetDir, "sub", "ours.conf"),
		[]byte(`SecRule ARGS "@rx x" "id:9504100,phase:1,deny"`), 0o644))

	overlaps, err := findRuleIDOverlaps(targetDir, RuleIDRange{Start: 9504000, End: 9504999}, []string{"sub/ours.conf"})

	s.Require().NoError(err)
	s.Equal([]string{"sub/nested-plugin.conf"}, overlaps)
}

func (s *installTestSuite) TestRecordInstall_MergesExisting() {
	pluginsDir := s.T().TempDir()

	s.Require().NoError(recordInstall(pluginsDir, "fake-bot", record{
		Repository: "https://github.com/coreruleset/fake-bot-plugin",
		Tag:        "v1.0.0",
		Digest:     "abc",
	}))
	s.Require().NoError(recordInstall(pluginsDir, "google-oauth2", record{
		Repository: "https://github.com/coreruleset/google-oauth2-plugin",
		Tag:        "v2.0.0",
		Digest:     "def",
	}))

	content, err := os.ReadFile(filepath.Join(pluginsDir, recordsFileName))
	s.Require().NoError(err)
	s.Contains(string(content), "fake-bot")
	s.Contains(string(content), "google-oauth2")
	s.Contains(string(content), "v1.0.0")
	s.Contains(string(content), "v2.0.0")
}

func (s *installTestSuite) TestInstall_EndToEnd() {
	// The registry fixture uses a real GitHub repository URL so
	// parseRepository can extract owner/repo; the actual API calls are
	// redirected to githubServer below via githubAPIBaseURL.
	registryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"plugins": [{
			"name": "fake-bot",
			"repository": "https://github.com/coreruleset/fake-bot-plugin",
			"rule_id_range": {"start": 9504000, "end": 9504999},
			"type": "official",
			"status": "tested",
			"license": "Apache-2.0"
		}]}`))
	}))
	defer registryServer.Close()

	githubServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/coreruleset/fake-bot-plugin/releases/latest":
			_, _ = w.Write([]byte(`{"tag_name": "v1.1.0"}`))
		case "/repos/coreruleset/fake-bot-plugin/tarball/v1.1.0":
			tarballPath := filepath.Join(s.T().TempDir(), "plugin.tar.gz")
			s.buildTarball(tarballPath, map[string]string{
				"fake-bot-plugin-abc123/plugins/fake-bot.conf": `SecRule ARGS "@rx x" "id:9504100,phase:1,deny"`,
			})
			content, err := os.ReadFile(tarballPath)
			s.Require().NoError(err)
			_, _ = w.Write(content)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer githubServer.Close()

	originalRegistryURL := registryURL
	originalGithubAPIBaseURL := githubAPIBaseURL
	registryURL = registryServer.URL
	githubAPIBaseURL = githubServer.URL
	defer func() {
		registryURL = originalRegistryURL
		githubAPIBaseURL = originalGithubAPIBaseURL
	}()

	pluginsDir := s.T().TempDir()
	result, err := Install(context.Background(), Options{Name: "fake-bot", PluginsDir: pluginsDir})

	s.Require().NoError(err)
	s.Equal("v1.1.0", result.Tag)
	s.Equal([]string{"fake-bot.conf"}, result.InstalledFiles)
	s.False(result.LuaWarning)
	s.Empty(result.OverlapWarnings)

	content, err := os.ReadFile(filepath.Join(pluginsDir, "fake-bot.conf"))
	s.Require().NoError(err)
	s.Contains(string(content), "id:9504100")

	_, err = os.Stat(filepath.Join(pluginsDir, recordsFileName))
	s.Require().NoError(err)

	// A second install without --force must refuse to overwrite.
	_, err = Install(context.Background(), Options{Name: "fake-bot", PluginsDir: pluginsDir})
	s.Require().Error(err)
	s.Contains(err.Error(), "refusing to overwrite")
}

func (s *installTestSuite) TestInstall_RequireSignatureFailsClosed() {
	registryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"plugins": [{
			"name": "fake-bot",
			"repository": "https://github.com/coreruleset/fake-bot-plugin",
			"rule_id_range": {"start": 9504000, "end": 9504999},
			"type": "official",
			"status": "tested",
			"license": "Apache-2.0"
		}]}`))
	}))
	defer registryServer.Close()

	originalRegistryURL := registryURL
	registryURL = registryServer.URL
	defer func() { registryURL = originalRegistryURL }()

	_, err := Install(context.Background(), Options{Name: "fake-bot", PluginsDir: s.T().TempDir(), RequireSignature: true})

	s.Require().Error(err)
	s.Contains(err.Error(), "does not publish a signed release artifact")
}

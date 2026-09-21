// Copyright 2026 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package plugin

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// recordsFileName holds, per plugins directory, what plugin install
// installed: name, resolved tag, source repository, and a digest of what
// landed on disk. `plugin list`/`upgrade` (future work) read this to tell
// what's installed and whether it still matches.
const recordsFileName = ".crs-toolchain-plugins.json"

// Options configures a single plugin install.
type Options struct {
	// Name is the plugin's name in the registry.
	Name string
	// Version pins a release tag. Empty resolves to the newest release.
	Version string
	// PluginsDir is the target directory plugin files are copied into.
	PluginsDir string
	// Force allows overwriting files already present in PluginsDir.
	Force bool
	// RequireSignature fails the install unless the release is signed. No
	// registered plugin publishes signed releases yet, so this always
	// fails today; it exists so an operator can ask for real verification
	// rather than get a silent, meaningless pass.
	RequireSignature bool
}

// Result reports what was installed, for the CLI to print.
type Result struct {
	Name            string
	Repository      string
	Tag             string
	Type            string
	Status          string
	RuleIDRange     RuleIDRange
	Digest          string
	InstalledFiles  []string
	LuaWarning      bool
	OverlapWarnings []string
}

type record struct {
	Repository  string      `json:"repository"`
	Tag         string      `json:"tag"`
	Digest      string      `json:"digest"`
	RuleIDRange RuleIDRange `json:"rule_id_range"`
	InstalledAt time.Time   `json:"installed_at"`
}

// Install resolves, downloads, and installs a plugin as described in
// options. It never overwrites existing files unless options.Force is set.
// The install is abandoned as soon as ctx is canceled.
func Install(ctx context.Context, options Options) (*Result, error) {
	entry, err := ResolvePlugin(ctx, options.Name)
	if err != nil {
		return nil, err
	}

	if options.RequireSignature {
		return nil, fmt.Errorf(
			"--require-signature was given, but %s does not publish a signed release artifact; "+
				"no registered CRS plugin does yet, so verification cannot be satisfied", entry.Name)
	}

	owner, repo, err := parseRepository(entry.Repository)
	if err != nil {
		return nil, err
	}

	client, err := newGitHubClient()
	if err != nil {
		return nil, err
	}

	tag, err := resolveTag(ctx, client, owner, repo, options.Version)
	if err != nil {
		return nil, err
	}

	tmpDir, err := os.MkdirTemp("", "crs-toolchain-plugin-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpDir)

	tarballPath := filepath.Join(tmpDir, "plugin.tar.gz")
	if err := downloadTarball(ctx, client, owner, repo, tag, tarballPath); err != nil {
		return nil, err
	}

	extractDir := filepath.Join(tmpDir, "extracted")
	relPaths, err := extractPluginFiles(tarballPath, extractDir)
	if err != nil {
		return nil, err
	}
	if len(relPaths) == 0 {
		return nil, fmt.Errorf("release %s of %s has no files under plugins/", tag, entry.Repository)
	}

	if err := os.MkdirAll(options.PluginsDir, 0o755); err != nil {
		return nil, err
	}

	if !options.Force {
		if conflicts := findConflicts(options.PluginsDir, relPaths); len(conflicts) > 0 {
			return nil, fmt.Errorf(
				"refusing to overwrite existing file(s) in %s: %s (use --force to overwrite)",
				options.PluginsDir, strings.Join(conflicts, ", "))
		}
	}

	digest, luaWarning, err := copyPluginFiles(extractDir, options.PluginsDir, relPaths)
	if err != nil {
		return nil, err
	}

	overlapWarnings, err := findRuleIDOverlaps(options.PluginsDir, entry.RuleIDRange, relPaths)
	if err != nil {
		return nil, err
	}

	if err := recordInstall(options.PluginsDir, entry.Name, record{
		Repository:  entry.Repository,
		Tag:         tag,
		Digest:      digest,
		RuleIDRange: entry.RuleIDRange,
		InstalledAt: time.Now().UTC(),
	}); err != nil {
		return nil, err
	}

	return &Result{
		Name:            entry.Name,
		Repository:      entry.Repository,
		Tag:             tag,
		Type:            entry.Type,
		Status:          entry.Status,
		RuleIDRange:     entry.RuleIDRange,
		Digest:          digest,
		InstalledFiles:  relPaths,
		LuaWarning:      luaWarning,
		OverlapWarnings: overlapWarnings,
	}, nil
}

// extractPluginFiles extracts the contents of the tarball's top-level
// plugins/ directory into destDir, preserving paths relative to plugins/.
// It returns those relative paths, sorted. Only regular files are
// extracted; directory and symlink entries are skipped, and entries that
// would escape destDir are rejected.
func extractPluginFiles(tarballPath, destDir string) ([]string, error) {
	file, err := os.Open(tarballPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	gzReader, err := gzip.NewReader(file)
	if err != nil {
		return nil, fmt.Errorf("reading archive: %w", err)
	}
	defer gzReader.Close()

	var relPaths []string
	tarReader := tar.NewReader(gzReader)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading archive: %w", err)
		}
		if header.Typeflag != tar.TypeReg {
			continue
		}

		// GitHub source tarballs wrap everything in a single top-level
		// "<owner>-<repo>-<sha>/" directory. We only want files under
		// that directory's "plugins/" subdirectory.
		segments := strings.Split(path.Clean(header.Name), "/")
		if len(segments) < 3 || segments[1] != "plugins" {
			continue
		}
		relPath := path.Join(segments[2:]...)
		if relPath == "." || strings.HasPrefix(relPath, "..") {
			continue
		}
		if relPath == recordsFileName {
			return nil, fmt.Errorf("release contains reserved path %q", relPath)
		}

		destPath := filepath.Join(destDir, filepath.FromSlash(relPath))
		if !strings.HasPrefix(destPath, filepath.Clean(destDir)+string(os.PathSeparator)) {
			return nil, fmt.Errorf("archive entry %q escapes destination", header.Name)
		}

		if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
			return nil, err
		}
		if err := extractFile(tarReader, destPath); err != nil {
			return nil, err
		}
		relPaths = append(relPaths, relPath)
	}

	sort.Strings(relPaths)
	return relPaths, nil
}

func extractFile(src io.Reader, destPath string) error {
	out, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, src); err != nil {
		return err
	}
	return out.Close()
}

// findConflicts returns the relPaths that already exist under targetDir. It
// uses Lstat, not Stat, so a dangling symlink planted at the destination is
// still reported as a conflict rather than silently followed on write.
func findConflicts(targetDir string, relPaths []string) []string {
	var conflicts []string
	for _, relPath := range relPaths {
		if _, err := os.Lstat(filepath.Join(targetDir, relPath)); err == nil {
			conflicts = append(conflicts, relPath)
		}
	}
	return conflicts
}

// copyPluginFiles copies relPaths from srcDir to destDir, and returns a
// digest of what was installed plus whether any file needs a Lua-enabled
// ModSecurity. The digest is computed from a manifest of per-file sha256
// hashes rather than the tarball itself, because GitHub's generated source
// archives are not guaranteed byte-stable across requests for the same tag;
// what a later `plugin list`/`upgrade` needs to know is whether the files on
// disk still match what was installed, and only a per-file digest answers
// that.
func copyPluginFiles(srcDir, destDir string, relPaths []string) (digest string, luaWarning bool, err error) {
	var manifest []string
	for _, relPath := range relPaths {
		hash, err := copyFile(filepath.Join(srcDir, relPath), filepath.Join(destDir, relPath))
		if err != nil {
			return "", false, err
		}
		manifest = append(manifest, relPath+":"+hash)
		if strings.HasSuffix(relPath, ".lua") {
			luaWarning = true
		}
	}

	sort.Strings(manifest)
	overall := sha256.Sum256([]byte(strings.Join(manifest, "\n")))
	return hex.EncodeToString(overall[:]), luaWarning, nil
}

func copyFile(srcPath, destPath string) (hexDigest string, err error) {
	src, err := os.Open(srcPath)
	if err != nil {
		return "", err
	}
	defer src.Close()

	if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
		return "", err
	}
	dest, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return "", err
	}
	defer dest.Close()

	hasher := sha256.New()
	if _, err := io.Copy(io.MultiWriter(dest, hasher), src); err != nil {
		return "", err
	}
	if err := dest.Close(); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

var ruleIDPattern = regexp.MustCompile(`\bid:\s*(\d+)`)

// findRuleIDOverlaps recursively scans the .conf files already present under
// targetDir (excluding the files this install just placed there) for
// ModSecurity rule IDs that fall inside ruleIDRange, and returns the paths of
// any that do, relative to targetDir.
func findRuleIDOverlaps(targetDir string, ruleIDRange RuleIDRange, ownRelPaths []string) ([]string, error) {
	own := make(map[string]bool, len(ownRelPaths))
	for _, relPath := range ownRelPaths {
		own[filepath.ToSlash(relPath)] = true
	}

	var overlaps []string
	err := filepath.WalkDir(targetDir, func(currentPath string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".conf") {
			return nil
		}
		relPath, err := filepath.Rel(targetDir, currentPath)
		if err != nil {
			return err
		}
		relPath = filepath.ToSlash(relPath)
		if own[relPath] {
			return nil
		}
		content, err := os.ReadFile(currentPath)
		if err != nil {
			return err
		}
		for _, match := range ruleIDPattern.FindAllStringSubmatch(string(content), -1) {
			id, err := strconv.Atoi(match[1])
			if err != nil {
				continue
			}
			if ruleIDRange.Contains(id) {
				overlaps = append(overlaps, relPath)
				break
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return overlaps, nil
}

// recordInstall adds or replaces name's entry in the install record file
// under pluginsDir, preserving the entries of any other installed plugins.
func recordInstall(pluginsDir, name string, rec record) error {
	recordsPath := filepath.Join(pluginsDir, recordsFileName)

	if info, err := os.Lstat(recordsPath); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symlink, refusing to read or write it", recordsPath)
	}

	records := map[string]record{}
	if content, err := os.ReadFile(recordsPath); err == nil {
		if err := json.Unmarshal(content, &records); err != nil {
			return fmt.Errorf("parsing %s: %w", recordsPath, err)
		}
	} else if !os.IsNotExist(err) {
		return err
	}

	records[name] = rec

	content, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(recordsPath, content, 0o644)
}

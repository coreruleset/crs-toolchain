// Copyright 2026 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

// Package plugin resolves, downloads, verifies, and installs CRS plugins
// published in the coreruleset/plugin-registry index.
package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

// registryURL is the stable, published, machine-readable index of registered
// CRS plugins. It is a var so tests can point it at an httptest server.
var registryURL = "https://raw.githubusercontent.com/coreruleset/plugin-registry/main/registry.json"

// registryTimeout bounds the time spent fetching the registry index.
var registryTimeout = 30 * time.Second

// registryMaxBytes bounds the registry index response body. The index is a
// small, hand-curated JSON file; anything near this size indicates a
// misbehaving or malicious host rather than a legitimate index.
const registryMaxBytes = 10 << 20 // 10 MiB

// RuleIDRange is the inclusive range of rule IDs a plugin is allocated.
type RuleIDRange struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

// Contains reports whether id falls within the range, inclusive.
func (r RuleIDRange) Contains(id int) bool {
	return id >= r.Start && id <= r.End
}

// RegistryEntry is one plugin's entry in the registry index. Only the fields
// an installer needs are decoded; plugin.yaml (description, config
// variables) is a configurator's concern, not the installer's.
type RegistryEntry struct {
	Name        string      `json:"name"`
	Repository  string      `json:"repository"`
	RuleIDRange RuleIDRange `json:"rule_id_range"`
	Type        string      `json:"type"`
	Status      string      `json:"status"`
	License     string      `json:"license"`
	Private     bool        `json:"private"`
}

type registryIndex struct {
	Plugins []RegistryEntry `json:"plugins"`
}

// UnknownPluginError is returned when a requested plugin name is not in the
// registry. It carries near-name matches so the CLI can suggest them.
type UnknownPluginError struct {
	Name        string
	NearMatches []string
}

func (e *UnknownPluginError) Error() string {
	if len(e.NearMatches) == 0 {
		return fmt.Sprintf("plugin %q not found in the registry", e.Name)
	}
	return fmt.Sprintf("plugin %q not found in the registry, did you mean: %s?",
		e.Name, strings.Join(e.NearMatches, ", "))
}

// ResolvePlugin fetches the published registry index and returns the entry
// matching name exactly. If no plugin matches, it returns an
// *UnknownPluginError listing names that contain the query as a substring.
func ResolvePlugin(name string) (*RegistryEntry, error) {
	entries, err := fetchRegistry()
	if err != nil {
		return nil, err
	}

	for i := range entries {
		if entries[i].Name == name {
			return &entries[i], nil
		}
	}

	return nil, &UnknownPluginError{Name: name, NearMatches: nearMatches(name, entries)}
}

// nearMatches returns up to 5 registry plugin names that contain query as a
// case-insensitive substring, sorted alphabetically.
func nearMatches(query string, entries []RegistryEntry) []string {
	lowerQuery := strings.ToLower(query)
	var matches []string
	for _, entry := range entries {
		if strings.Contains(strings.ToLower(entry.Name), lowerQuery) {
			matches = append(matches, entry.Name)
		}
	}
	sort.Strings(matches)
	if len(matches) > 5 {
		matches = matches[:5]
	}
	return matches
}

func fetchRegistry() ([]RegistryEntry, error) {
	ctx, cancel := context.WithTimeout(context.Background(), registryTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, registryURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching plugin registry: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("fetching plugin registry: unexpected status %s", resp.Status)
	}

	var index registryIndex
	if err := json.NewDecoder(io.LimitReader(resp.Body, registryMaxBytes)).Decode(&index); err != nil {
		return nil, fmt.Errorf("parsing plugin registry: %w", err)
	}

	return index.Plugins, nil
}

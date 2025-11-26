package chore

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/Masterminds/semver/v3"
)

const (
	versionTableEntrySupportedMarker             = ":white_check_mark:"
	versionTableEntryNotSupportedMarker          = ":x:"
	newVersionTableEntryTemplate                 = "| %s%s| %s%s|"
	versionColumnWidth                           = 10
	supportedColumnWidth                         = 19
	numberOfSupportedMinorVersionsInCurrentMajor = 2
	numberOfSupportedMinorVersionsInLegacyMajors = 1
	numberOfSupportedLegacyMajorVersions         = 1
)

type versionTable struct {
	entries []versionTableEntry
}

type versionTableEntry struct {
	versionString string
	version       *semver.Version
	supported     bool
}

func newVersionTable(lines []string) (*versionTable, error) {
	table := &versionTable{
		entries: make([]versionTableEntry, 0, len(lines)),
	}
	for _, line := range lines {
		entry, err := newVersionTableEntry(line)
		if err != nil {
			return nil, err
		}
		table.Append(entry)
	}

	return table, nil
}

func newVersionTableEntry(line string) (*versionTableEntry, error) {
	segments := strings.Split(line, "|")
	if len(segments) != 4 {
		logger.Warn().Msgf("failed to parse version table entry %s", line)
		return nil, errors.New("invalid version table entry")
	}
	versionString := strings.TrimSpace(segments[1])
	patchedVersionString := strings.ReplaceAll(versionString, "x", "0")
	patchedVersionString = strings.ReplaceAll(patchedVersionString, "y", "0")
	patchedVersionString = strings.ReplaceAll(patchedVersionString, "z", "0")
	patchedVersionString = strings.ReplaceAll(patchedVersionString, "2.x", "2.0.0")

	version, err := semver.NewVersion(patchedVersionString)
	if err != nil {
		logger.Warn().Msgf("failed to parse version from %s", line)
		return nil, errors.New("invalid version in table entry")
	}

	entry := &versionTableEntry{
		versionString: versionString,
		version:       version,
		supported:     strings.Contains(segments[2], versionTableEntrySupportedMarker),
	}

	return entry, nil
}

func (v *versionTable) Append(entry *versionTableEntry) {
	v.entries = append(v.entries, *entry)
}

func (v *versionTable) Prepend(entry *versionTableEntry) {
	v.entries = slices.Insert(v.entries, 0, *entry)
}

func (v *versionTable) ToLines() []string {
	lines := make([]string, 0, len(v.entries))
	for _, entry := range v.entries {
		supportedMarker := versionTableEntryNotSupportedMarker
		if entry.supported {
			supportedMarker = versionTableEntrySupportedMarker
		}
		versionColumnPadding := strings.Repeat(" ", versionColumnWidth-len(entry.versionString))
		supportedColumnPadding := strings.Repeat(" ", supportedColumnWidth-len(supportedMarker))
		lines = append(lines, fmt.Sprintf(newVersionTableEntryTemplate, entry.versionString, versionColumnPadding, supportedMarker, supportedColumnPadding))
	}
	return append(lines, "")
}

func (v *versionTable) updateVersionSupport(newMajorVersion uint64) {
	lastMajorVersion := uint64(0)
	sameMajorVersionCount := 1
	for i := range v.entries {
		entry := &v.entries[i]
		currentMajor := entry.version.Major()
		if currentMajor == lastMajorVersion {
			sameMajorVersionCount++
		} else {
			sameMajorVersionCount = 1
		}
		if sameMajorVersionCount > numberOfSupportedMinorVersionsInLegacyMajors && currentMajor < newMajorVersion {
			entry.supported = false
		} else if sameMajorVersionCount > numberOfSupportedMinorVersionsInCurrentMajor && currentMajor == newMajorVersion {
			entry.supported = false
		} else if currentMajor < newMajorVersion-numberOfSupportedLegacyMajorVersions {
			entry.supported = false
		} else {
			entry.supported = true
		}
		lastMajorVersion = currentMajor
	}
}

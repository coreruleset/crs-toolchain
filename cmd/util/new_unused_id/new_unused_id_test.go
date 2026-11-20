// Copyright 2026 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package newUnusedId

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/coreruleset/crs-toolchain/v2/cmd/internal"
)

func TestNewUnusedId_RequiresRange(t *testing.T) {
	cmd := New(internal.NewCommandContext(t.TempDir()))
	cmd.SetArgs([]string{})
	assert.Error(t, cmd.Execute())
}

func TestNewUnusedId_PrintsId(t *testing.T) {
	root := t.TempDir()
	assert.NoError(t, os.MkdirAll(filepath.Join(root, "rules"), 0755))
	assert.NoError(t, os.WriteFile(filepath.Join(root, "rules", "REQUEST-942-APPLICATION-ATTACK-SQLI.conf"), []byte(`SecRule ARGS "@rx a" "id:942100"`), 0644))

	out := &bytes.Buffer{}
	cmd := New(internal.NewCommandContext(root))
	cmd.SetOut(out)
	cmd.SetArgs([]string{"942"})
	assert.NoError(t, cmd.Execute())
	assert.Equal(t, "942110\n", out.String())
}

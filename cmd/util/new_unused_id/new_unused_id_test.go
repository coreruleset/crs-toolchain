// Copyright 2026 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package newUnusedId

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/coreruleset/crs-toolchain/v2/cmd/internal"
)

func TestNewUnusedId_RequiresRange(t *testing.T) {
	cmd := New(internal.NewCommandContext(t.TempDir()))
	cmd.SetArgs([]string{})
	assert.Error(t, cmd.Execute())
}

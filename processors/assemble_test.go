// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package processors

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewAssemble(t *testing.T) {
	assemble := NewAssemble(NewContext("rootdir", "namespace"))

	assert.NotNil(t, assemble)
	assert.Equal(t, assemble.proc.ctx.rootDirectory, "rootdir")
	assert.Equal(t, assemble.proc.ctx.dataFilesDirectory, "rootdir/data")
}

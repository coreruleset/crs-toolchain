package processors

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNewAssemble(t *testing.T) {
	assemble := NewAssemble(NewContext("rootdir", "namespace"))

	assert.NotNil(t, assemble)
	assert.Equal(t, assemble.proc.ctx.rootDirectory, "rootdir")
	assert.Equal(t, assemble.proc.ctx.dataFilesDirectory, "rootdir/data")
}

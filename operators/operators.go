package operators

import (
	"github.com/rs/zerolog/log"
	"github.com/theseion/crs-toolchain/v2/processors"
	"io"
)

var logger = log.With().Str("component", "operators").Logger()

type Operator struct {
	//TODO: define operator
	stats *Stats
	ctx   *processors.Context
}

type IOperator interface {
	Preprocess(io.Reader)
	Run(io.Reader)
}

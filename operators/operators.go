package operators

import (
	"github.com/rs/zerolog/log"
	"github.com/theseion/crs-toolchain/v2/processors"
	"io"
)

var logger = log.With().Str("component", "operators").Logger()

type Operator struct {
	name    string
	details map[string]string
	lines   []string
	stats   *Stats
	ctx     *processors.Context
}

type OperatorStack []*Operator

type IOperator interface {
	Preprocess(io.Reader)
	Run(io.Reader)
}

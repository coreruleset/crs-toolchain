package internal

import (
	"errors"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/coreruleset/crs-toolchain/v2/context"
	"github.com/coreruleset/crs-toolchain/v2/regex"
	"github.com/coreruleset/crs-toolchain/v2/regex/operators"
	"github.com/coreruleset/crs-toolchain/v2/regex/processors"
)

func ParseRuleId(idAndChainOffset string, cmdContext *CommandContext) error {
	cmdContext.UseStdin = false

	subs := regex.RuleIdFileNameRegex.FindAllStringSubmatch(idAndChainOffset, -1)
	if subs == nil {
		return errors.New("failed to match rule ID")
	}

	fileName := subs[0][0]
	id := subs[0][1]
	chainOffsetString := subs[0][2]

	chainOffset, err := strconv.ParseUint(chainOffsetString, 10, 8)
	if err != nil && len(chainOffsetString) > 0 {
		return errors.New("failed to match chain offset. Value must not be larger than 255")
	}

	if !strings.HasSuffix(fileName, ".ra") {
		fileName += ".ra"
	}

	cmdContext.Id = id
	cmdContext.FileName = fileName
	cmdContext.ChainOffset = uint8(chainOffset)

	return nil
}

func RunAssemble(filePath string, rootContext *context.Context, cmdContext *CommandContext) string {
	ctxt := processors.NewContext(rootContext)
	assembler := operators.NewAssembler(ctxt)
	var input []byte
	var err error
	if cmdContext.UseStdin {
		cmdContext.Logger.Trace().Msg("Reading from stdin")
		input, err = io.ReadAll(os.Stdin)
		if err != nil {
			cmdContext.Logger.Fatal().Err(err).Msg("Failed to read from stdin")
		}
	} else {
		cmdContext.Logger.Trace().Msgf("Reading from %s", filePath)
		input, err = os.ReadFile(filePath)
		if err != nil {
			cmdContext.Logger.Fatal().Err(err).Msgf("Failed to read regex-assembly file %s", filePath)
		}
	}
	assembly, err := assembler.Run(string(input))
	if err != nil {
		cmdContext.Logger.Fatal().Err(err).Send()
	}
	return assembly
}

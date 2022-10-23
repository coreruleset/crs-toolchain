package cmd

import (
	"errors"
	"regexp"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

// generateCmd represents the generate command
var regexCmd = createRegexCommand()
var ruleIdRegex *regexp.Regexp
var ruleValues struct {
	id          string
	fileName    string
	chainOffset uint8
	useStdin    bool
}

func init() {
	ruleIdRegex = regexp.MustCompile(`^(\d{6})(?:-chain(\d+))?(?:\.data)?$`)
	buildRegexCommand()
}

func createRegexCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "regex",
		Short: "Commands that process regular expressions",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return nil
			}
			err := parseRuleId(args[0])
			if err != nil {
				cmd.PrintErrf("failed to parse the rule ID from the input '%s'\n", args[0])
				return err
			}

			return nil
		},
	}

}

func buildRegexCommand() {
	rootCmd.AddCommand(regexCmd)
}

func rebuildRegexCommand() {
	if regexCmd != nil {
		regexCmd.Parent().RemoveCommand(regexCmd)
		ruleValues.id = ""
		ruleValues.fileName = ""
		ruleValues.chainOffset = 0
		ruleValues.useStdin = false
	}

	generateCmd = createRegexCommand()
	buildRegexCommand()
}

func parseRuleId(idAndChainOffset string) error {
	// Validation has already occurred, so we know that when the value
	// is `-`, it's ok.
	if idAndChainOffset == "-" {
		ruleValues.useStdin = true
		return nil
	}

	ruleValues.useStdin = false

	subs := ruleIdRegex.FindAllStringSubmatch(idAndChainOffset, -1)
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

	if !strings.HasSuffix(fileName, ".data") {
		fileName += ".data"
	}

	ruleValues.id = id
	ruleValues.fileName = fileName
	ruleValues.chainOffset = uint8(chainOffset)

	return nil
}

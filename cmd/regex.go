package cmd

import (
	"github.com/spf13/cobra"
)

// generateCmd represents the generate command
var regexCmd = createRegexCommand()

func init() {
	buildRegexCommand()
}

func createRegexCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "regex",
		Short: "Commands that process regular expressions",
	}

}

func buildRegexCommand() {
	rootCmd.AddCommand(regexCmd)
}

func rebuildRegexCommand() {
	if regexCmd != nil {
		regexCmd.Parent().RemoveCommand(regexCmd)
	}

	generateCmd = createRegexCommand()
	buildRegexCommand()
}

package cmd

import (
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

const defaultLogLevel = zerolog.ErrorLevel

// rootCmd represents the base command when called without any subcommands
var rootCmd = createRootCommand()
var logger zerolog.Logger
var rootValues struct {
	output   outputType
	logLevel logLevel
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	zerolog.SetGlobalLevel(defaultLogLevel)
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: "03:04:05"})
	logger = log.With().Str("component", "cmd").Logger()

	buildRootCommand()
}

func createRootCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "crs-toolchain",
		Short: "The Core Ruleset toolchain",
	}
}

func buildRootCommand() {
	rootCmd.PersistentFlags().VarP(&rootValues.logLevel, "log-level", "l",
		`Set the application log level. Default: 'error'.
Options: 'trace', 'debug', 'info', 'warn', 'error', 'fatal', 'panic', 'disabled`)
	rootCmd.PersistentFlags().VarP(&rootValues.output, "output", "o", "Output format. One of 'text', 'github'. Default: 'text'")
}

func rebuildRootCommand() {
	rootCmd = createRootCommand()
	rootValues.output = "text"
	rootValues.logLevel = logLevel(defaultLogLevel.String())

	buildRootCommand()
}

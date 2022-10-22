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
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			logLevelString, err := cmd.Flags().GetString("log-level")
			if err != nil {
				logger.Error().Err(err).Msg("Failed to read log level from command line")
				return err
			}
			logLevel, err := zerolog.ParseLevel(logLevelString)
			if err != nil {
				logger.Error().Err(err).Msgf("Failed to parse log level '%s'", logLevelString)
				return err
			}
			zerolog.SetGlobalLevel(logLevel)
			logger.Debug().Msgf("Set log level to '%s'", logLevel)

			return nil
		},
	}
}

func buildRootCommand() {
	rootCmd.PersistentFlags().StringP("log-level", "l", "error",
		`Set the application log level. Default is 'error'.
Options: 'trace', 'debug', 'info', 'warn', 'error', 'fatal', 'panic', 'disabled`)
}

func rebuildRootCommand() {
	rootCmd = createRootCommand()
	buildRootCommand()
}

package cmd

import (
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = createRootCommand()

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	buildRootCommand()
}

func createRootCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "v2",
		Short: "A brief description of your application",
		Long: `A longer description that spans multiple lines and likely contains
examples and usage of using your application. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			logLevelString, err := cmd.Flags().GetString("log-level")
			if err != nil {
				log.Error().Err(err).Msg("Failed to read log level from command line")
				os.Exit(1)
			}
			logLevel, err := zerolog.ParseLevel(logLevelString)
			if err != nil {
				log.Error().Err(err).Msgf("Failed to parse log level '%s'", logLevelString)
			}
			log.Debug().Msgf("Set log level to '%s'", logLevel)
			zerolog.SetGlobalLevel(logLevel)
		},
	}
}

func buildRootCommand() {
	rootCmd.PersistentFlags().String("log-level", "error", "Set the application log level. Default is 'error'")
}

func rebuildRootCommand() {
	rootCmd = createRootCommand()
	buildRootCommand()
}

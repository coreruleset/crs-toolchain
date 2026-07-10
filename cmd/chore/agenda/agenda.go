package agenda

import (
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	chore "github.com/coreruleset/crs-toolchain/v2/chore/agenda"
	"github.com/coreruleset/crs-toolchain/v2/cmd/internal"
)

func New(cmdContext *internal.CommandContext) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create-agenda",
		Short: "Create new agenda for monthly chat",
		Long: `Create new agenda for monthly chat. Requires a valid GitHub API token in the environment.
The command will fetch the "Agenda-Next" wiki page and replace the template strings, then use the result
to create the new chat agenda issue.
Finally, the command will reset the "Agenda-Next" wiki page.`,
		Args: cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			printOnly, err := cmd.Flags().GetBool("print")
			if err != nil {
				log.Fatal().Err(err).Send()
			}
			chore.Agenda(printOnly)
		},
	}
	buildFlags(cmd)
	return cmd
}

func buildFlags(cmd *cobra.Command) {
	cmd.Flags().Bool("print", false, "Print the generated agenda instead of creating an issue on GitHub")
}

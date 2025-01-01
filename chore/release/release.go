package chore

import (
	"errors"
	"fmt"
	"os/exec"
	"time"

	"github.com/Masterminds/semver/v3"
	copyright "github.com/coreruleset/crs-toolchain/v2/chore/update_copyright"
	"github.com/coreruleset/crs-toolchain/v2/context"
	"github.com/go-git/go-git/v5"
	"github.com/rs/zerolog/log"
)

var logger = log.With().Str("component", "release").Logger()

func Release(context *context.Context, repositoryPath string, version *semver.Version, sourceRef string) {
	createAndCheckOutBranch(context, fmt.Sprintf("v%d.%d.%d", version.Major(), version.Minor(), version.Patch()), sourceRef)
	copyright.UpdateCopyright(context, version, uint16(time.Now().Year()))
	createCommit(context, version)
}

func createAndCheckOutBranch(context *context.Context, branchName string, sourceRef string) {
	if err := checkForCleanWorkTree(context); err != nil {
		// FIXME
		panic(err)
	}

	out, err := runGit(context.RootDir(), "switch", "-c", branchName, sourceRef)
	if err != nil {
		logger.Fatal().Err(err).Bytes("command-output", out).Msg("failed to create commit for release")
	}
}

func createCommit(context *context.Context, version *semver.Version) {
	out, err := runGit(context.RootDir(), "commit", "-am", "Release "+fmt.Sprintf("v%d.%d.%d", version.Major(), version.Minor(), version.Patch()))
	if err != nil {
		logger.Fatal().Err(err).Bytes("command-output", out).Msg("failed to create commit for release")
	}
}

func checkForCleanWorkTree(context *context.Context) error {
	repositoryPath := context.RootDir()
	repo, err := git.PlainOpen(repositoryPath)
	if err != nil {
		//FIXME
		panic(err)
	}
	worktree, err := repo.Worktree()
	if err != nil {
		//FIXME
		panic(err)
	}
	status, err := worktree.Status()
	if err != nil {
		//FIXME
		panic(err)
	}
	if !status.IsClean() {
		// FIXME
		return errors.New("worktree not clean. Please stash or commit your changes first")
	}
	return nil
}

func runGit(repositoryPath string, args ...string) ([]byte, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = repositoryPath
	return cmd.CombinedOutput()
}

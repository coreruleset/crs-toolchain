package chore

import (
	"errors"
	"fmt"
	"os/exec"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/coreruleset/crs-toolchain/v2/context"
	"github.com/go-git/go-git/v5"
)

func Release(context *context.Context, repositoryPath string, version *semver.Version, sourceRef string) {
	createAndCheckOutBranch(context, fmt.Sprintf("v%d.%d.%d", version.Major(), version.Minor(), version.Patch()), sourceRef)
	UpdateCopyright(context, version, uint16(time.Now().Year()))
	createCommit(context, version)
}

func createAndCheckOutBranch(context *context.Context, branchName string, sourceRef string) {
	if err := checkForCleanWorkTree(context); err != nil {
		// FIXME
		panic(err)
	}

	cmd := exec.Command("git", "switch", "-c", branchName, sourceRef)
	cmd.Dir = context.RootDir()
	out, err := cmd.CombinedOutput()
	print(out)
	if err != nil {
		//FIXME
		panic(err)
	}
}

func createCommit(context *context.Context, version *semver.Version) {
	cmd := exec.Command("git", "commit", "-am", "Release "+fmt.Sprintf("v%d.%d.%d", version.Major(), version.Minor(), version.Patch()))
	err := cmd.Run()
	if err != nil {
		//FIXME
		panic(err)
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

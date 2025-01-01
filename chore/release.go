package chore

import (
	"fmt"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/coreruleset/crs-toolchain/v2/context"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
)

func Release(context *context.Context, repositoryPath string, version *semver.Version) {
	createAndCheckOutBranch(context, fmt.Sprintf("v%d.%d.%d", version.Major(), version.Minor(), version.Patch()))
	UpdateCopyright(context, version, uint16(time.Now().Year()))
}

func createAndCheckOutBranch(context *context.Context, branchName string) {
	repositoryPath := context.RootDir()
	r, err := git.PlainOpen(repositoryPath)
	if err != nil {
		//FIXME
		panic(err)
	}
	headRef, err := r.Head()
	if err != nil {
		//FIXME
		panic(err)
	}

	// Create a new plumbing.HashReference object with the name of the branch
	// and the hash from the HEAD. The reference name should be a full reference
	// name and not an abbreviated one, as is used on the git cli.
	refName := plumbing.ReferenceName("refs/heads/" + branchName)
	ref := plumbing.NewHashReference(refName, headRef.Hash())

	// The created reference is saved in the storage.
	err = r.Storer.SetReference(ref)
	if err != nil {
		//FIXME
		panic(err)
	}
	branch := &config.Branch{
		Name:  branchName,
		Merge: refName,
	}
	err = r.CreateBranch(branch)
	if err != nil {
		//FIXME
		panic(err)
	}

	branchCoOpts := git.CheckoutOptions{
		Branch: refName,
		Force:  true,
	}
	w, err := r.Worktree()
	if err != nil {
		//FIXME
		panic(err)
	}

	if err := w.Checkout(&branchCoOpts); err != nil {
		//FIXME
		panic(err)
	}
}

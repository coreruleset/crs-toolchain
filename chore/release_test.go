package chore

import (
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/stretchr/testify/suite"
)

type choreReleaseTestSuite struct {
	suite.Suite
	repoDir string
}

func (s *choreReleaseTestSuite) SetupTest() {
	s.repoDir = s.T().TempDir()
	repo, err := git.PlainInit(s.repoDir, false)
	s.Require().NoError(err)

	w, err := repo.Worktree()
	s.Require().NoError(err)
	commit, err := w.Commit("dummy", &git.CommitOptions{
		Author: &object.Signature{
			Name:  "Homer Simpson",
			Email: "doughnuts@simpsons.com",
			When:  time.Now(),
		},
		AllowEmptyCommits: true,
	})
	s.Require().NoError(err)
	_, err = repo.CommitObject(commit)
	s.Require().NoError(err)
}

func TestRunChoreReleaseTestSuite(t *testing.T) {
	suite.Run(t, new(choreReleaseTestSuite))
}

func (s *choreReleaseTestSuite) TestCreateBranch() {
	branchName := "v1.2.3"
	createAndCheckOutBranch(s.repoDir, branchName)
	repo, err := git.PlainOpen(s.repoDir)
	s.Require().NoError(err)

	branch, err := repo.Branch(branchName)
	s.Require().NoError(err, "Branch should have been created")

	headRef, err := repo.Head()
	s.Require().NoError(err)

	branchHash, err := repo.ResolveRevision(plumbing.Revision(branch.Name))
	s.Require().NoError(err)
	s.Equal(*branchHash, headRef.Hash(), "New branch should have been checked out")
}

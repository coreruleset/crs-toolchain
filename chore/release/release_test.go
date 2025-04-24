package chore

import (
	"fmt"
	"os"
	"os/exec"
	"path"
	"testing"

	"github.com/Masterminds/semver/v3"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/stretchr/testify/suite"

	"github.com/coreruleset/crs-toolchain/v2/configuration"
	"github.com/coreruleset/crs-toolchain/v2/context"
)

type choreReleaseTestSuite struct {
	suite.Suite
	repoDir string
}

func (s *choreReleaseTestSuite) SetupTest() {
	s.repoDir = s.T().TempDir()

	out, err := runGit(s.repoDir, "init", "-b", "main")
	s.Require().NoError(err, string(out))

	out, err = runGit(s.repoDir, "config", "user.email", "dummy@dummy.com")
	s.Require().NoError(err, string(out))

	out, err = runGit(s.repoDir, "config", "user.name", "dummy")
	s.Require().NoError(err, string(out))

	out, err = runGit(s.repoDir, "commit", "--allow-empty", "-m", "dummy")
	s.Require().NoError(err, string(out))
}

func TestRunChoreReleaseTestSuite(t *testing.T) {
	suite.Run(t, new(choreReleaseTestSuite))
}

func (s *choreReleaseTestSuite) TestCreateAndcheckoutBranch() {
	branchName := "v1.2.3"
	ctxt := context.New(s.repoDir, "")
	createAndCheckOutBranch(ctxt, branchName, "main")
	repo, err := git.PlainOpen(s.repoDir)
	s.Require().NoError(err)

	branches, err := repo.Branches()
	s.Require().NoError(err)

	found := false
	var branchRef *plumbing.Reference
	err = branches.ForEach(func(r *plumbing.Reference) error {
		if r.Name().Short() == branchName {
			found = true
			branchRef = r
		}
		return nil
	})
	s.Require().NoError(err)
	s.True(found)

	headRef, err := repo.Head()
	s.Require().NoError(err)

	s.Equal(branchRef.Hash(), headRef.Hash(), "New branch should have been checked out")
}

func (s *choreReleaseTestSuite) TestCreateCommit() {
	branchName := "v1.2.3"
	ctxt := context.New(s.repoDir, "")
	createAndCheckOutBranch(ctxt, branchName, "main")

	// Add something to commit, as `createCommit` doesn't allow empty commits
	err := os.WriteFile(path.Join(s.repoDir, "file"), []byte("content"), os.ModePerm)
	s.Require().NoError(err)
	cmd := exec.Command("git", "add", ".")
	cmd.Dir = s.repoDir
	err = cmd.Run()
	s.Require().NoError(err)

	createCommit(ctxt, branchName)

	repo, err := git.PlainOpen(s.repoDir)
	s.Require().NoError(err)
	worktree, err := repo.Worktree()
	s.Require().NoError(err)
	status, err := worktree.Status()
	s.Require().NoError(err)
	s.True(status.IsClean())

	// HEAD has the new commit message
	revision, err := repo.ResolveRevision("HEAD")
	s.Require().NoError(err)
	commit, err := repo.CommitObject(*revision)
	s.Require().NoError(err)
	s.Equal(fmt.Sprintf("chore: release %s\n", branchName), commit.Message)

	// parent of HEAD is main
	parent, err := commit.Parent(0)
	s.Require().NoError(err)
	branchHash, err := repo.ResolveRevision(plumbing.Revision("main"))
	s.Require().NoError(err)
	s.Equal(*branchHash, parent.Hash)
}

func (s *choreReleaseTestSuite) TestUpdateVersionTable_NewMinor() {
	contents := `
Some lorem ipsum garbage

| Version   | Supported          |
| --------- | ------------------ |
| 4.13.z    | :white_check_mark: |
| 4.12.z    | :white_check_mark: |
| 4.y.z     | :x:                |
| 3.3.x     | :white_check_mark: |
| 3.2.x     | :x:                |
| 3.1.x     | :x:                |
| 3.0.x     | :x:                |
| 2.x       | :x:                |

More garbage.
`
	expected := `
Some lorem ipsum garbage

| Version   | Supported          |
| --------- | ------------------ |
| 4.14.z    | :white_check_mark: |
| 4.13.z    | :white_check_mark: |
| 4.12.z    | :x:                |
| 4.y.z     | :x:                |
| 3.3.x     | :white_check_mark: |
| 3.2.x     | :x:                |
| 3.1.x     | :x:                |
| 3.0.x     | :x:                |
| 2.x       | :x:                |

More garbage.
`
	filePath := path.Join(s.repoDir, securityReadmeFileName)
	err := os.WriteFile(filePath, []byte(contents), os.ModePerm)
	s.Require().NoError(err)
	version, err := semver.NewVersion("4.14.0")
	s.Require().NoError(err)
	context := context.NewWithConfiguration(s.repoDir, &configuration.Configuration{})
	updateSecurityReadme(context, version)

	newContents, err := os.ReadFile(filePath)
	s.Require().NoError(err)
	s.Equal(expected, string(newContents))
}

func (s *choreReleaseTestSuite) TestUpdateVersionTable_NewMajor() {
	contents := `
Some lorem ipsum garbage

| Version   | Supported          |
| --------- | ------------------ |
| 4.13.z    | :white_check_mark: |
| 4.12.z    | :white_check_mark: |
| 4.y.z     | :x:                |
| 3.3.x     | :white_check_mark: |
| 3.2.x     | :x:                |
| 3.1.x     | :x:                |
| 3.0.x     | :x:                |
| 2.x       | :x:                |

More garbage.
`
	expected := `
Some lorem ipsum garbage

| Version   | Supported          |
| --------- | ------------------ |
| 5.0.z     | :white_check_mark: |
| 4.13.z    | :white_check_mark: |
| 4.12.z    | :x:                |
| 4.y.z     | :x:                |
| 3.3.x     | :x:                |
| 3.2.x     | :x:                |
| 3.1.x     | :x:                |
| 3.0.x     | :x:                |
| 2.x       | :x:                |

More garbage.
`
	filePath := path.Join(s.repoDir, securityReadmeFileName)
	err := os.WriteFile(filePath, []byte(contents), os.ModePerm)
	s.Require().NoError(err)
	version, err := semver.NewVersion("5.0.0")
	s.Require().NoError(err)
	context := context.NewWithConfiguration(s.repoDir, &configuration.Configuration{})
	updateSecurityReadme(context, version)

	newContents, err := os.ReadFile(filePath)
	s.Require().NoError(err)
	s.Equal(expected, string(newContents))
}

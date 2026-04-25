package chore

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/cli/go-gh/v2/pkg/api"
	"github.com/go-git/go-git/v5"
	"github.com/rs/zerolog/log"

	copyright "github.com/coreruleset/crs-toolchain/v2/chore/update_copyright"
	"github.com/coreruleset/crs-toolchain/v2/context"
)

const (
	examplesPath           = "util/crs-rules-check/examples"
	branchNameTemplate     = "release/v%d.%d.%d"
	prTitleTemplate        = "chore: release v%d.%d.%d"
	securityReadmeFileName = "SECURITY.md"
	versionTableMarker     = "| Version"
)

var logger = log.With().Str("component", "release").Logger()

func Release(context *context.Context, repositoryPath string, version *semver.Version, sourceRef string) {
	remoteName := findRemoteName()
	if remoteName == "" {
		logger.Fatal().Msg("failed to find remote for coreruleset/coreruleset")
	}
	fetchSourceRef(remoteName, sourceRef)
	branchName := fmt.Sprintf(branchNameTemplate, version.Major(), version.Minor(), version.Patch())
	createAndCheckOutBranch(context, branchName, sourceRef)
	copyright.UpdateCopyright(context, version, uint16(time.Now().Year()), []string{examplesPath})
	updateSecurityReadme(context, version)
	createCommit(context, branchName)
	pushBranch(remoteName, branchName)
	createPullRequest(version, branchName, sourceRef)
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

func createCommit(context *context.Context, branchName string) {
	out, err := runGit(context.RootDir(), "commit", "-am", "chore: release "+branchName)
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

func createPullRequest(version *semver.Version, branchName string, targetBranchName string) {
	opts := api.ClientOptions{
		Headers: map[string]string{"Accept": "application/octet-stream"},
	}
	client, err := api.NewRESTClient(opts)
	if err != nil {
		log.Fatal().Err(err).Send()
	}

	type prBody struct {
		Title    string   `json:"title"`
		Head     string   `json:"head"`
		Base     string   `json:"base"`
		Labels   []string `json:"labels"`
		Reviewer string   `json:"reviewer"`
	}
	bodyJson, err := json.Marshal(&prBody{
		Title:    fmt.Sprintf(prTitleTemplate, version.Major(), version.Minor(), version.Patch()),
		Head:     "coreruleset:" + branchName,
		Base:     targetBranchName,
		Labels:   []string{"release", "release:ignore"},
		Reviewer: "coreruleset/core-developers",
	})
	if err != nil {
		log.Fatal().Err(err).Msg("failed to serialize body of GH REST request")
	}

	response, err := client.Request(http.MethodPost, "repos/coreruleset/coreruleset/pulls", bytes.NewReader(bodyJson))
	if err != nil {
		log.Fatal().Err(err).Msg("creating PR failed")
	}
	defer response.Body.Close()
}

func pushBranch(remoteName string, branchName string) {
	out, err := runGit("push", remoteName, branchName)
	if err != nil {
		logger.Fatal().Err(err).Bytes("command-output", out)
	}
}

func fetchSourceRef(remoteName string, sourceRef string) {
	out, err := runGit("fetch", remoteName, sourceRef)
	if err != nil {
		logger.Fatal().Err(err).Bytes("command-output", out)
	}
}

func runGit(repositoryPath string, args ...string) ([]byte, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = repositoryPath
	return cmd.CombinedOutput()
}

func findRemoteName() string {
	out, err := runGit("remote", "-v")
	if err != nil {
		logger.Fatal().Err(err).Bytes("command-output", out)
	}
	var remoteName string
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "coreruleset/coreruleset") {
			remoteName = strings.Split(line, " ")[0]
		}
	}

	return remoteName
}

func updateSecurityReadme(context *context.Context, newVersion *semver.Version) {
	logger.Info().Msgf("updating supported version information in %s", securityReadmeFileName)

	filePath := path.Join(context.RootDir(), securityReadmeFileName)
	_, err := os.Stat(filePath)
	if os.IsNotExist(err) {
		logger.Warn().Msgf("%s not found, cannot update supported version information", securityReadmeFileName)
		return
	} else if err != nil {
		logger.Warn().Err(err).Msgf("failed to stat %s", securityReadmeFileName)
		return
	}

	contents, err := os.ReadFile(filePath)
	if err != nil {
		logger.Warn().Err(err).Msgf("failed to read from %s", securityReadmeFileName)
		return
	}

	lines := make([]string, 0, 100)
	scanner := bufio.NewScanner(bytes.NewReader(contents))
	found := false
	for scanner.Scan() {
		line := scanner.Text()
		lines = append(lines, line)
		if strings.HasPrefix(line, versionTableMarker) {
			found = true
			// append table header separator line
			scanner.Scan()
			lines = append(lines, scanner.Text())
			patchedLines, err := updateVersionTable(scanner, newVersion)
			if err != nil {
				return
			}
			lines = append(lines, patchedLines...)
		}
	}
	if !found {
		logger.Warn().Msgf("Did not find version table in %s", securityReadmeFileName)
		return
	}

	lines = append(lines, "")
	err = os.WriteFile(filePath, []byte(strings.Join(lines, "\n")), 0)
	if err != nil {
		logger.Warn().Err(err).Msgf("failed to write %s", securityReadmeFileName)
	}
}

func updateVersionTable(scanner *bufio.Scanner, newVersion *semver.Version) ([]string, error) {
	lines := make([]string, 0, 15)
	for scanner.Scan() {
		line := scanner.Text()
		if len(strings.TrimSpace(line)) == 0 {
			break
		}
		lines = append(lines, line)
	}
	newVersionTable, err := newVersionTable(lines)
	if err != nil {
		return nil, err
	}

	// Add the newly supported version
	newVersionTable.Prepend(&versionTableEntry{
		versionString: fmt.Sprintf("%d.%d.z", newVersion.Major(), newVersion.Minor()),
		version:       newVersion,
		supported:     true,
	})
	newVersionTable.updateVersionSupport(newVersion.Major())

	return newVersionTable.ToLines(), nil
}

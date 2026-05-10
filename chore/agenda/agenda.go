package agenda

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cli/go-gh/v2/pkg/api"
	"github.com/rs/zerolog/log"

	_ "embed"

	"github.com/coreruleset/crs-toolchain/v2/utils"
)

var logger = log.With().Str("component", "agenda").Logger()

//go:embed agenda-next.md
var agendaNextTemplate []byte

func Agenda() {
	opts := api.ClientOptions{
		Headers: map[string]string{"Accept": "application/vnd.github+json"},
	}
	client, err := api.NewRESTClient(opts)
	if err != nil {
		logger.Fatal().Err(err).Send()
	}

	type issueBody struct {
		Title  string   `json:"title"`
		Body   string   `json:"body"`
		Labels []string `json:"labels"`
	}
	nextDate := computeNextDate(time.Now())
	previousDate := computePreviousDate(time.Now())
	month := nextDate.Month().String()
	year := nextDate.Year()
	dateString := nextDate.Format(time.DateOnly)
	logger.Info().Msgf("Computed previous and next chat dates as: %s, %s", previousDate.Format(time.DateOnly), dateString)

	logger.Info().Msg("Cloning wiki repository")
	tempDir, err := os.MkdirTemp("", "crs-wiki")
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to create temporary directory for cloning the wiki repository")
	}
	defer func() {
		err := os.RemoveAll(tempDir)
		if err != nil {
			logger.Error().Err(err).Msgf("Failed to delete wiki directory %s", tempDir)
		}
	}()
	cloneWiki(tempDir, "wiki")
	wikiDir := filepath.Join(tempDir, "wiki")

	bodyJson, err := json.Marshal(&issueBody{
		Title:  fmt.Sprintf("Monthly Chat Agenda %s %d (%s)", month, year, dateString),
		Labels: []string{":bookmark: Meeting Agenda"},
		Body:   buildAgendaBody(client, wikiDir, previousDate, nextDate),
	})
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to serialize body of GH REST request")
	}

	logger.Info().Msg("Creating new agenda issue")
	response, err := client.Request(http.MethodPost, "repos/coreruleset/coreruleset/issues", bytes.NewReader(bodyJson))
	if err != nil {
		logger.Fatal().Err(err).Msg("creating agenda failed")
	}
	defer response.Body.Close()

	logger.Info().Msg("New Agenda successfully created")

	logger.Info().Msg(`Resetting "Agenda-Next" wiki page`)
	resetAgendaNext(wikiDir)
	logger.Info().Msg("Done")
}

func resetAgendaNext(wikiDir string) {
	if err := os.WriteFile(filepath.Join(wikiDir, "Agenda-Next.md"), agendaNextTemplate, 0644); err != nil {
		logger.Fatal().Msg(`failed to write "Agenda-Next.md"`)
	}
	out, err := utils.RunGit(wikiDir, "commit", "-m", "Reset Agenda-Next.md", "Agenda-Next.md")
	if err != nil {
		logger.Fatal().Err(err).Msgf(`failed to commit "Agenda-Next": %s`, out)
	}
	out, err = utils.RunGit(wikiDir, "push")
	if err != nil {
		logger.Fatal().Err(err).Msgf(`failed to push "Agenda-Next": %s`, out)
	}
}

func buildAgendaBody(client *api.RESTClient, wikiDir string, previousDate time.Time, nextDate time.Time) string {
	logger.Info().Msg("Building issue body")
	agendaPath := filepath.Join(wikiDir, "Agenda-Next.md")
	template, err := os.ReadFile(agendaPath)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to read meeting agenda")
	}

	logger.Info().Msg("Fetching PR statistics from GitHub")
	mergedPrs := getMergedPrsString(client, previousDate)
	openPrs := getOpenPrsString(client)
	wipPrs := getWipPrsString(client)

	logger.Info().Msg("Updating agenda with computed information")
	prsString := fmt.Sprintf(`### PRs that have been merged since the last meeting

%s

### Open PRs

%s

### Open PRs marked *DRAFT* or *work in progress* or *needs action*

%s`,
		mergedPrs, openPrs, wipPrs)
	templateString := strings.Replace(string(template), "{{PR_STATS}}", prsString, 1)
	return strings.Replace(templateString, "{{CHAT_DATE}}", nextDate.Format(time.DateOnly), 1)
}

func cloneWiki(path string, repoName string) {
	remoteCandidates := []string{
		"git@github.com:coreruleset/coreruleset.wiki.git",
		"https://github.com/coreruleset/coreruleset.wiki.git",
	}
	succeeded := false
	for _, remote := range remoteCandidates {
		logger.Debug().Msgf("Cloning wiki with remote %s", remote)
		out, err := utils.RunGit(path, "clone", remote, repoName)
		if err != nil {
			logger.Warn().Err(err).Msgf("failed to clone coreruleset wiki: %s", out)
			continue
		}
		succeeded = true
		break
	}
	if !succeeded {
		logger.Fatal().Msg("failed to clone wiki using both SSH and HTTPS; giving up")
	}

}

func getMergedPrsString(client *api.RESTClient, since time.Time) string {
	prs := searchPrs(client, fmt.Sprintf("is:pr is:merged closed:>=%s", since.Format(time.DateOnly)), "updated", "desc")
	logger.Debug().Msgf("Found %d merged PRs", len(prs))
	return buildPrsString(prs)
}

func getOpenPrsString(client *api.RESTClient) string {
	prs := searchPrs(client, `is:pr is:open draft:false -label:"needs action","work in progress"`, "updated", "desc")
	logger.Debug().Msgf("Found %d open PRs", len(prs))
	return buildPrsString(prs)
}

func getWipPrsString(client *api.RESTClient) string {
	prs := searchPrs(client, `is:pr is:open label:"needs action","work in progress"`, "interactions", "desc")
	logger.Debug().Msgf("Found %d WIP PRs", len(prs))
	return buildPrsString(prs)
}

func buildPrsString(prs []int) string {
	sb := strings.Builder{}
	for i, id := range prs {
		if _, err := fmt.Fprintf(&sb, "- #%d", id); err != nil {
			logger.Fatal().Err(err).Msg("Failed to write string buffer")
		}
		if i < len(prs)-1 {
			if _, err := sb.WriteRune('\n'); err != nil {
				logger.Fatal().Err(err).Msg("Failed to write string buffer")
			}
		}
	}

	prsString := sb.String()
	if len(prsString) == 0 {
		return "N/A"
	}

	return prsString
}

func searchPrs(client *api.RESTClient, query string, sort string, order string) []int {
	searchQuery := url.QueryEscape(query + " repo:coreruleset/coreruleset")
	// We don't use pagination for now and simply expect that we don't exceed 100 results
	url := fmt.Sprintf("%s?q=%s&sort=%s&order=%s&per_page=100", "search/issues", searchQuery, sort, order)
	logger.Debug().Msgf("Searching for PRs with: %s", url)

	response := struct {
		Items []struct {
			Number int
		}
	}{}
	err := client.Get(url, &response)
	if err != nil {
		logger.Fatal().Err(err).Msg("Fetching PRs failed")
	}

	ids := []int{}
	for _, item := range response.Items {
		ids = append(ids, item.Number)
	}
	return ids
}

func computeNextDate(now time.Time) time.Time {
	firstMonday := computeFirstMondayOfMonth(now.Year(), now.Month())
	if firstMonday.Day() < now.Day() {
		return computeFirstMondayOfMonth(now.Year(), now.Month()+1)
	}
	return firstMonday
}

func computePreviousDate(now time.Time) time.Time {
	firstMonday := computeFirstMondayOfMonth(now.Year(), now.Month())
	if firstMonday.Day() < now.Day() {
		return firstMonday
	}
	return computeFirstMondayOfMonth(now.Year(), now.Month()-1)
}

func computeFirstMondayOfMonth(year int, month time.Month) time.Time {
	firstOfMonth := time.Date(year, month, 1, 0, 0, 0, 0, time.UTC)
	day := (8-firstOfMonth.Weekday())%7 + 1
	return time.Date(year, month, int(day), 0, 0, 0, 0, time.UTC)
}

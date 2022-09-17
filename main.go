package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/google/go-github/v47/github"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
)

type CVEInfo struct {
	ID          string `json:"id"`
	GithubUrl   string `json:"url"`
	ExternalUrl string `json:"external_url"`
	Summary     string `json:"summary"`
}

type K8sCVEs struct {
	Items []CVEInfo `json:"items"`
}

type ById []CVEInfo

func (a ById) Len() int           { return len(a) }
func (a ById) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ById) Less(i, j int) bool { return a[i].ID > a[j].ID }

func init() {
	log.SetFormatter(&log.JSONFormatter{})
	log.SetOutput(os.Stdout)
	log.SetLevel(log.InfoLevel)
}

func main() {
	url := os.Getenv("CVE_FEED")

	httpClient := http.Client{
		Timeout: time.Second * 10,
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		log.Fatal(err)
	}

	req.Header.Set("User-Agent", "kubernetes-sec-alert")

	res, err := httpClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	if res.Body != nil {
		defer res.Body.Close()
	}

	body, readErr := io.ReadAll(res.Body)
	if readErr != nil {
		log.Fatal(readErr)
	}

	var k8scves K8sCVEs
	err = json.Unmarshal(body, &k8scves)
	if err != nil {
		log.Fatal(err)
	}
	sort.Sort(sort.Reverse(ById(k8scves.Items)))

	ctx := context.Background()
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: os.Getenv("GH_TOKEN")},
	)
	tc := oauth2.NewClient(ctx, ts)
	client := github.NewClient(tc)

	for _, cve := range k8scves.Items {
		issueLabel := strings.ToLower(cve.ID)
		_, _, err := client.Issues.GetLabel(ctx, os.Getenv("REPO_OWNER"), os.Getenv("REPO_NAME"), issueLabel)
		if err != nil {
			labelColor := "d82521"
			label := &github.Label{Name: &issueLabel, Color: &labelColor}
			_, _, err = client.Issues.CreateLabel(ctx, os.Getenv("REPO_OWNER"), os.Getenv("REPO_NAME"), label)
			if err != nil {
				log.Warn("Failed to create label, ", err)
			} else {
				log.Info("Label " + issueLabel + " created")
			}
		}
		searchQuery := "user:" + os.Getenv("REPO_OWNER") + "repo:" + os.Getenv("REPO_NAME") + " label:" + issueLabel
		existingIssues, _, err := client.Search.Issues(ctx, searchQuery, nil)
		if err != nil {
			log.Warn(err)
		}
		totalIssues := existingIssues.Total
		if int(*totalIssues) == 0 {
			issueTitle := cve.ID + ": " + cve.Summary
			issueBody := fmt.Sprintf("Github URL: %s", cve.GithubUrl)
			issue := &github.IssueRequest{
				Title:  &issueTitle,
				Labels: &[]string{issueLabel},
				Body:   &issueBody,
			}
			_, _, err := client.Issues.Create(ctx, os.Getenv("REPO_OWNER"), os.Getenv("REPO_NAME"), issue)
			if err != nil {
				log.Warn("Failed to issue, ", err)
			} else {
				log.Info("Issue " + issueLabel + " created")
			}
		}
	}
}

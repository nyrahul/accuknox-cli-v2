package common

import (
	"context"

	"github.com/google/go-github/github"
)

// SetupGitHubClient sets up a GitHub client with the provided PAT, it uses oAuth2 to authenticate
func SetupGitHubClient(ctx context.Context) (*github.Client, error) {

	client := github.NewClient(nil)

	return client, nil
}

// GetLatestRelease returns the latest release from the GitHub API
func GetLatestRelease(client *github.Client, ctx context.Context) (*github.RepositoryRelease, error) {
	latestRelease, _, err := client.Repositories.GetLatestRelease(ctx, AccuknoxGithub, AccuknoxKnoxctlwebsite)
	if err != nil {
		return nil, err
	}

	return latestRelease, nil
}

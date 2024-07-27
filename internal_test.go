package internal_test

import (
	"testing"

	"github.com/tobiasthedanish/go-report/internal"

	_ "github.com/joho/godotenv/autoload"
)

func TestGithubService(t *testing.T) {
	if _, err := internal.NewGithubService(); err != nil {
		t.Fatalf("Initialization of github service failed with error: %s\n", err)
	}
}

func TestGetJWT(t *testing.T) {
	service, err := internal.NewGithubService()
	if err != nil {
		t.Fatalf("Initialization of github service failed with error: %s\n", err)
	}

	token, err := service.GetJWT()
	if err != nil {
		t.Fatalf("Creating JWT for github service failed with err: %s", err)
	}

	if token == "" {
		t.Fatal("Created JWT Token for github is not valid")
	}
}

func TestGithubGetInstallation(t *testing.T) {
	service, err := internal.NewGithubService()
	if err != nil {
		t.Fatalf("Initialization of github service failed with error: %s\n", err)
	}

	userInstall, err := service.GetUserInstallation("TobiasTheDanish")
	if err != nil {
		t.Fatalf("Getting user installation failed with error: %s\n", err)
	}

	if userInstall.GetId() <= 0 {
		t.Fatalf("User installtion id of %d is invalid.\n", userInstall.GetId())
	}
}

func TestGithubGetInstallationAccess(t *testing.T) {
	service, err := internal.NewGithubService()
	if err != nil {
		t.Fatalf("Initialization of github service failed with error: %s\n", err)
	}

	userInstall, err := service.GetUserInstallation("TobiasTheDanish")
	if err != nil {
		t.Fatalf("Getting user installation failed with error: %s\n", err)
	}

	access, err := service.GetInstallationAccessToken(userInstall)
	if err != nil {
		t.Fatalf("Getting installation access token failed with error: %s\n", err)
	}

	if access.Token == "" {
		t.Fatalf("returned Installation access token is invalid")
	}
}

func TestGithubCreateIssue(t *testing.T) {
	service, err := internal.NewGithubService()
	if err != nil {
		t.Fatalf("Initialization of github service failed with error: %s\n", err)
	}

	res, err := service.CreateIssue("TobiasTheDanish", "go-report", "Test issue", internal.CreateIssueOptions{Body: "### Issue test\n\nThis is the issue description", Labels: []string{"bug"}, Assignees: []string{"TobiasTheDanish"}})
	if err != nil {
		t.Fatalf("Creating github issue failed with err: %s", err)
	}

	if res.Id <= 0 || res.HtmlUrl == "" || res.Number <= 0 {
		t.Fatalf("Invalid issueResponse:\nIssue id: %d\nIssue url: %s\nIssue number: %d\n", res.Id, res.HtmlUrl, res.Number)
	}
}

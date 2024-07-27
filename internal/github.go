package internal

import (
	"bytes"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt"
)

type GithubService interface {
	CreateIssue(owner string, repo string, title string, options ...CreateIssueOptions) (CreateIssueRes, error)
}

type githubService struct {
	AppId      string
	ClientId   string
	privateKey *rsa.PrivateKey
}

func NewGithubService() (GithubService, error) {
	data, err := os.ReadFile(os.Getenv("GITHUB_PRIVATE_KEY_PATH"))
	if err != nil {
		return nil, err
	}

	private, err := jwt.ParseRSAPrivateKeyFromPEM(data)
	if err != nil {
		return nil, err
	}

	return &githubService{
		AppId:      os.Getenv("GITHUB_APP_ID"),
		ClientId:   os.Getenv("GITHUB_CLIENT_ID"),
		privateKey: private,
	}, nil
}

func (s *githubService) GetJWT() (string, error) {
	now := time.Now()
	issuedAt := now.Unix() - 60
	expires := now.Unix() + 5*60

	signer := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iat": issuedAt,
		"exp": expires,
		"iss": s.ClientId,
		"alg": "RS256",
	})

	return signer.SignedString(s.privateKey)
}

type issueBodyBuilder struct {
	body createIssueBody
}

func (b *issueBodyBuilder) Build() createIssueBody {
	return b.body
}
func (b *issueBodyBuilder) WithOptions(options CreateIssueOptions) *issueBodyBuilder {
	b.body.Body = options.Body
	if options.Assignees != nil {
		b.body.Assignees = options.Assignees
	}
	if options.Milestone != "" {
		b.body.Milestone = &options.Milestone
	}
	if options.Labels != nil {
		b.body.Labels = options.Labels
	}

	return b
}
func (s *githubService) issueBodyBuilder(title string) *issueBodyBuilder {
	return &issueBodyBuilder{
		body: createIssueBody{
			Title:     title,
			Assignees: make([]string, 0),
			Labels:    make([]string, 0),
			Milestone: nil,
		},
	}
}

type CreateIssueOptions struct {
	Body      string
	Assignees []string
	Milestone string
	Labels    []string
}
type createIssueBody struct {
	Title     string   `json:"title"`
	Body      string   `json:"body"`
	Assignees []string `json:"assignees"`
	Milestone *string  `json:"milestone"`
	Labels    []string `json:"labels"`
}
type CreateIssueRes struct {
	Id      int64  `json:"id"`
	HtmlUrl string `json:"html_url"`
	Number  int    `json:"number"`
}

func (s *githubService) CreateIssue(owner string, repo string, title string, options ...CreateIssueOptions) (CreateIssueRes, error) {
	userInstallation, err := s.GetUserInstallation(owner)
	if err != nil {
		return CreateIssueRes{}, err
	}

	access, err := s.GetInstallationAccessToken(userInstallation)
	if err != nil {
		return CreateIssueRes{}, err
	}

	issueBuilder := s.issueBodyBuilder(title)
	if len(options) > 0 {
		issueBuilder.WithOptions(options[0])
	}

	issue := issueBuilder.Build()
	reqBody, err := json.Marshal(issue)
	if err != nil {
		return CreateIssueRes{}, err
	}

	bodyReader := bytes.NewReader(reqBody)
	reqUrl := fmt.Sprintf("https://api.github.com/repos/%s/%s/issues", owner, repo)
	req, err := http.NewRequest(http.MethodPost, reqUrl, bodyReader)
	if err != nil {
		return CreateIssueRes{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", access.Token))
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return CreateIssueRes{}, err
	}

	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		return CreateIssueRes{}, err
	}

	if res.StatusCode != 201 {
		return CreateIssueRes{}, errors.New(fmt.Sprintf("Creating issue for repo: '%s/%s', failed with body: %s", owner, repo, resBody))
	}

	var issueRes CreateIssueRes
	err = json.Unmarshal(resBody, &issueRes)
	if err != nil {
		return CreateIssueRes{}, err
	}

	return issueRes, nil
}

type installation interface {
	GetId() int
}

type userInstallationRes struct {
	Id int `json:"id"`
}

func (i userInstallationRes) GetId() int { return i.Id }

func (s *githubService) GetUserInstallation(username string) (installation, error) {
	token, err := s.GetJWT()
	if err != nil {
		return nil, err
	}

	reqUrl := fmt.Sprintf("https://api.github.com/users/%s/installation", username)
	req, err := http.NewRequest(http.MethodGet, reqUrl, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	if res.StatusCode != 200 {
		return nil, errors.New(fmt.Sprintf("Getting installation for user: '%s', failed with body: %s", username, resBody))
	}

	var installationRes userInstallationRes
	err = json.Unmarshal(resBody, &installationRes)
	if err != nil {
		return nil, err
	}

	return installationRes, nil
}

type installationAccess struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
}

func (s *githubService) GetInstallationAccessToken(i installation) (*installationAccess, error) {
	token, err := s.GetJWT()
	if err != nil {
		return nil, err
	}

	reqUrl := fmt.Sprintf("https://api.github.com/app/installations/%d/access_tokens", i.GetId())
	req, err := http.NewRequest(http.MethodPost, reqUrl, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	if res.StatusCode != 201 {
		return nil, errors.New(fmt.Sprintf("Creating installation access token for id: %d, failed with body: %s", i.GetId(), resBody))
	}

	var access installationAccess
	err = json.Unmarshal(resBody, &access)
	if err != nil {
		return nil, err
	}

	return &access, nil
}

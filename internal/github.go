package internal

import (
	"bytes"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/golang-jwt/jwt"
)

type GithubService interface {
	CreateIssue(owner string, repo string, title string, options ...CreateIssueOptions) (CreateIssueRes, error)
	AuthUserByCode(code string) (AuthUserRes, error)
	GetAuthorizedUser(auth AuthUserRes) (AuthorizedUser, error)
	GetAuthorizedUserOrgs(orgUrl string, auth AuthUserRes) ([]AuthorizedUserOrg, error)
	HandleWebhook(payload []byte) error
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

type AuthUserRes struct {
	AccessToken           string `json:"access_token"`
	ExpiresIn             int    `json:"expires_in"`
	RefreshToken          string `json:"refresh_token"`
	RefreshTokenExpiresIn int    `json:"refresh_token_expires_in"`
	Scope                 string `json:"scope"`
	TokenType             string `json:"token_type"`
}

func (s *githubService) AuthUserByCode(code string) (AuthUserRes, error) {
	clientId := os.Getenv("GITHUB_CLIENT_ID")
	clientSecret := os.Getenv("GITHUB_CLIENT_SECRET")

	reqUrl := "https://github.com/login/oauth/access_token?"
	reqVals, err := url.ParseQuery(fmt.Sprintf("code=%s&client_id=%s&client_secret=%s", code, clientId, clientSecret))
	if err != nil {
		return AuthUserRes{}, errors.Join(errors.New("Parsing request query parameters failed"), err)
	}
	reqBody := bytes.NewReader([]byte(reqVals.Encode()))

	req, err := http.NewRequest(http.MethodPost, reqUrl, reqBody)
	if err != nil {
		return AuthUserRes{}, errors.Join(errors.New("Creating request for authentication failed."), err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return AuthUserRes{}, errors.Join(errors.New("Getting from oauth url failed."), err)
	}

	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		return AuthUserRes{}, errors.Join(errors.New("Reading response body failed."), err)
	}

	if res.StatusCode != 200 {
		return AuthUserRes{}, errors.New(fmt.Sprintf("Authentication with code '%s', failed with body: %s", code, resBody))
	}

	var authRes AuthUserRes
	err = json.Unmarshal(resBody, &authRes)
	if err != nil {
		return AuthUserRes{}, errors.Join(errors.New("Unmarshalling response body failed."), err)
	}

	return authRes, nil
}

type AuthorizedUser struct {
	Username string `json:"login"`
	OrgUrl   string `json:"organizations_url"`
}

func (s *githubService) GetAuthorizedUser(auth AuthUserRes) (AuthorizedUser, error) {
	reqUrl := "https://api.github.com/user"
	req, err := http.NewRequest(http.MethodGet, reqUrl, nil)
	if err != nil {
		return AuthorizedUser{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", auth.AccessToken))
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return AuthorizedUser{}, err
	}

	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		return AuthorizedUser{}, err
	}

	var user AuthorizedUser
	if err := json.Unmarshal(resBody, &user); err != nil {
		return AuthorizedUser{}, err
	}

	return user, nil
}

type AuthorizedUserOrg struct {
	Name string `json:"login"`
}

func (s *githubService) GetAuthorizedUserOrgs(orgUrl string, auth AuthUserRes) ([]AuthorizedUserOrg, error) {
	req, err := http.NewRequest(http.MethodGet, orgUrl, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", auth.AccessToken))
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	var orgs []AuthorizedUserOrg
	if err := json.Unmarshal(resBody, &orgs); err != nil {
		return nil, err
	}

	return orgs, nil
}

func (s *githubService) HandleWebhook(payload []byte) error {
	fmt.Println(string(payload))

	return nil
}

package internal

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/a-h/templ"
	"github.com/go-playground/validator/v10"
	_ "github.com/joho/godotenv/autoload"
	"github.com/tobiasthedanish/go-report/internal/view"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

type Server struct {
	port int

	dbService DatabaseService
	ghService GithubService
}

func NewServer() (*http.Server, error) {
	port, err := strconv.Atoi(os.Getenv("PORT"))
	if err != nil {
		return nil, err
	}
	s, err := NewGithubService()
	if err != nil {
		return nil, err
	}
	db, err := NewDatabaseService()
	if err != nil {
		return nil, nil
	}
	NewServer := &Server{
		port:      port,
		dbService: db,
		ghService: s,
	}

	// Declare Server config
	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", NewServer.port),
		Handler:      NewServer.RegisterRoutes(),
		IdleTimeout:  time.Minute,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	return server, nil
}

type CustomValidator struct {
	v *validator.Validate
}

func (v *CustomValidator) Validate(i interface{}) error {
	return v.v.Struct(i)
}

func (s *Server) RegisterRoutes() http.Handler {
	e := echo.New()
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Validator = &CustomValidator{v: validator.New()}

	e.GET("/sign-in", s.SignInHandler)
	e.GET("/auth/callback", s.GithubAuthCallbackHandler)
	e.POST("/api/:repo/issues", s.PostIssueHandler)
	e.POST("/gh/webhook", s.GithubWebhookHandler)
	return e
}

type postIssueData struct {
	Repo    string `param:"repo" validate:"required"`
	Title   string `json:"title" validate:"required"`
	Options struct {
		Body      string   `json:"body"`
		Assignees []string `json:"assignees" validate:"unique"`
		Milestone string   `json:"milestone"`
		Labels    []string `json:"labels" validate:"unique"`
	} `json:"options"`
}

func (s *Server) PostIssueHandler(c echo.Context) error {
	var data postIssueData
	if err := c.Bind(&data); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err)
	}
	if err := c.Validate(data); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err)
	}

	issue, err := s.ghService.CreateIssue("TobiasTheDanish", data.Repo, data.Title, CreateIssueOptions(data.Options))
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	return c.JSON(201, issue)
}

func (s *Server) SignInHandler(c echo.Context) error {
	clientId := os.Getenv("GITHUB_CLIENT_ID")
	authUrl := fmt.Sprintf("https://github.com/login/oauth/authorize?client_id=%s", clientId)

	return view.SignIn(templ.URL(authUrl)).Render(c.Request().Context(), c.Response().Writer)
}

type AuthCallbackData struct {
	Code string `query:"code"`
}

func (s *Server) GithubAuthCallbackHandler(c echo.Context) error {
	var data AuthCallbackData
	if err := c.Bind(&data); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err)
	}

	auth, err := s.ghService.AuthUserByCode(data.Code)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	user, err := s.ghService.GetAuthorizedUser(auth)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	orgs, err := s.ghService.GetAuthorizedUserOrgs(user.OrgUrl, auth)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	fmt.Printf("Authorized user: '%s'\nOrgs: %v\n", user.Username, orgs)

	return c.JSON(http.StatusOK, map[string]any{
		"user": user,
		"orgs": orgs,
	})
}

func (s *Server) GithubWebhookHandler(c echo.Context) error {
	body, err := io.ReadAll(c.Request().Body)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, fmt.Errorf("Could not read body from webhook request. Error: %s\n", err.Error()))
	}

	s.ghService.HandleWebhook(body)

	return c.JSON(http.StatusNoContent, nil)
}

type InstallationData struct {
	Owner string `json:"owner" validata:"required"`
}

func (s *Server) CreateInstallation(c echo.Context) error {
	var data InstallationData
	if err := c.Bind(&data); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err)
	}

	if err := c.Validate(data); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err)
	}

	return c.JSON(http.StatusCreated, nil)
}

package internal

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/go-playground/validator/v10"
	_ "github.com/joho/godotenv/autoload"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

type Server struct {
	port int

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
	NewServer := &Server{
		port:      port,
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

	e.POST("/api/:repo/issues", s.PostIssueHandler)

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

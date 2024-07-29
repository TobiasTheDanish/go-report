package server

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
	"github.com/tobiasthedanish/go-report/internal/db"
	"github.com/tobiasthedanish/go-report/internal/github"
	"github.com/tobiasthedanish/go-report/internal/server/auth"
	"github.com/tobiasthedanish/go-report/internal/view"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

type Server struct {
	port int

	dbService db.DatabaseService
	ghService github.GithubService
}

func NewServer() (*http.Server, error) {
	port, err := strconv.Atoi(os.Getenv("PORT"))
	if err != nil {
		return nil, err
	}
	s, err := github.NewGithubService()
	if err != nil {
		return nil, err
	}
	db, err := db.NewDatabaseService()
	if err != nil {
		return nil, err
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
	e.Static("assets/", "assets")

	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Validator = &CustomValidator{v: validator.New()}

	// Authentication
	e.GET("/sign-in", s.SignInHandler)
	e.GET("/auth/callback", s.GithubAuthCallbackHandler)

	// HTML Handlers
	e.GET("/", s.IndexHandler)
	e.GET("/token/:ownerName", s.GetTokenModal)
	e.POST("/token/:ownerName", s.GenerateToken)

	// JSON Handlers
	e.POST("/api/:repo/issues", s.PostIssueHandler)
	e.POST("/api/installations", s.CreateInstallation)

	// Webhooks
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
	jwtString, err := auth.GetJWTString(c.Request().Header)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, err)
	}

	owner, err := auth.ParseOwnerJWT(jwtString)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, err)
	}

	issue, err := s.ghService.CreateIssue(owner.Name, data.Repo, data.Title, github.CreateIssueOptions(data.Options))
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	return c.JSON(201, issue)
}

func (s *Server) IndexHandler(c echo.Context) error {
	jwtCookie, err := c.Request().Cookie("authSession")
	if err != nil {
		fmt.Printf("Could not get cookie with name authSession: %s\n", err)
		return c.Redirect(http.StatusTemporaryRedirect, "/sign-in?error=Authorization%20failed")
	}

	session, err := auth.ParseAuthJWT(jwtCookie.Value)
	if err != nil {
		fmt.Printf("Error when parsing jwt: %s\n", err)
		return c.Redirect(http.StatusTemporaryRedirect, "/sign-in?error=Authorization%20failed")
	}

	return view.Index(session).Render(c.Request().Context(), c.Response().Writer)
}

func (s *Server) SignInHandler(c echo.Context) error {
	errorMsg := c.QueryParam("error")

	clientId := os.Getenv("GITHUB_CLIENT_ID")
	authUrl := fmt.Sprintf("https://github.com/login/oauth/authorize?client_id=%s", clientId)

	return view.SignIn(templ.URL(authUrl), errorMsg).Render(c.Request().Context(), c.Response().Writer)
}

type AuthCallbackData struct {
	Code string `query:"code"`
}

func (s *Server) GithubAuthCallbackHandler(c echo.Context) error {
	var data AuthCallbackData
	if err := c.Bind(&data); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err)
	}

	authUser, err := s.ghService.AuthUserByCode(data.Code)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	user, err := s.ghService.GetAuthorizedUser(authUser)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	owners := make([]db.Owner, 0)
	userOwner, err := s.dbService.ReadOwner(user.Username)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}
	if userOwner.Id != -1 {
		owners = append(owners, userOwner)
	}

	orgs, err := s.ghService.GetAuthorizedUserOrgs(user.OrgUrl, authUser)
	if err == nil {
		for _, org := range orgs {
			owner, err := s.dbService.ReadOwner(org.Name)
			if err != nil {
				return echo.NewHTTPError(http.StatusInternalServerError, err)
			}
			if owner.Id != -1 {
				owners = append(owners, owner)
			}
		}
	} else {
		fmt.Println(err.Error())
	}

	jwtString, err := auth.SignAuthSession(auth.AuthSession{
		Username: user.Username,
		Owners:   owners,
	})
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	http.SetCookie(c.Response().Writer, &http.Cookie{
		Name:   "authSession",
		Value:  jwtString,
		MaxAge: int(24 * time.Hour),
		Path:   "/",
	})

	return c.Redirect(http.StatusTemporaryRedirect, "/")
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

	newOwner, err := s.dbService.CreateOwnerIfNotExists(data.Owner)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	i, err := s.dbService.CreateInstallation(newOwner.Id)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	return c.JSON(http.StatusCreated, map[string]any{
		"owner":        newOwner,
		"installation": i,
	})
}

func (s *Server) GetTokenModal(c echo.Context) error {
	var data struct {
		OwnerName string `param:"ownerName"`
	}
	if err := c.Bind(&data); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err)
	}
	jwtCookie, err := c.Request().Cookie("authSession")
	if err != nil {
		fmt.Printf("Could not get cookie with name authSession: %s\n", err)
		return c.Redirect(http.StatusTemporaryRedirect, "/sign-in")
	}

	session, err := auth.ParseAuthJWT(jwtCookie.Value)
	if err != nil {
		fmt.Printf("Error when parsing jwt: %s\n", err)
		return c.Redirect(http.StatusTemporaryRedirect, "/sign-in")
	}

	allowed := false
	for _, owner := range session.Owners {
		if owner.Name == data.OwnerName {
			allowed = true
		}
	}

	if !allowed {
		return c.Redirect(http.StatusTemporaryRedirect, "/sign-in")
	}

	return view.AuthTokenModal(data.OwnerName).Render(c.Request().Context(), c.Response().Writer)
}

func (s *Server) GenerateToken(c echo.Context) error {
	var data struct {
		OwnerName string `param:"ownerName"`
	}
	if err := c.Bind(&data); err != nil {
		return view.AuthTokenContainer("Invalid data").Render(c.Request().Context(), c.Response().Writer)
	}
	jwtCookie, err := c.Request().Cookie("authSession")
	if err != nil {
		fmt.Printf("Could not get cookie with name authSession: %s\n", err)
		return c.Redirect(http.StatusTemporaryRedirect, "/sign-in")
	}

	session, err := auth.ParseAuthJWT(jwtCookie.Value)
	if err != nil {
		fmt.Printf("Error when parsing jwt: %s\n", err)
		return c.Redirect(http.StatusTemporaryRedirect, "/sign-in")
	}

	allowed := false
	for _, owner := range session.Owners {
		if owner.Name == data.OwnerName {
			allowed = true
		}
	}

	if !allowed {
		return c.Redirect(http.StatusTemporaryRedirect, "/sign-in")
	}

	owner, err := s.dbService.ReadOwner(data.OwnerName)
	if err != nil || owner.Id == -1 {
		return view.AuthTokenContainer(fmt.Sprintf("Could not find owner '%s'", data.OwnerName)).Render(c.Request().Context(), c.Response().Writer)
	}

	token, err := auth.SignAuthOwner(auth.AuthOwner(owner))
	if err != nil {
		return view.AuthTokenContainer(fmt.Sprintf("Could not sign owner. Err: '%s'", err.Error())).Render(c.Request().Context(), c.Response().Writer)
	}

	return view.AuthTokenContainer(token).Render(c.Request().Context(), c.Response().Writer)
}

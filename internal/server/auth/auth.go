package auth

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/tobiasthedanish/go-report/internal/db"
)

func sign(claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return token.SignedString([]byte(os.Getenv("JWT_SECRET")))
}

type AuthSession struct {
	Username string     `json:"username"`
	Owners   []db.Owner `json:"owners"`
}

type sessionClaims struct {
	Session AuthSession `json:"session"`
	jwt.RegisteredClaims
}

func GetJWTString(h http.Header) (string, error) {
	authorization := h.Get("Authorization")
	authSplit := strings.Split(authorization, " ")
	if len(authSplit) != 2 {
		return "", fmt.Errorf("Missing authorization header")
	}

	if strings.ToLower(authSplit[0]) != "bearer" {
		return "", fmt.Errorf("Unauthorized")
	}

	return authSplit[1], nil
}

func SignAuthSession(session AuthSession) (string, error) {
	now := time.Now()
	claims := sessionClaims{
		session,
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
			Issuer:    os.Getenv("JWT_ISSUER"),
		},
	}

	return sign(claims)
}

func ParseAuthJWT(jwtString string) (AuthSession, error) {
	token, err := jwt.ParseWithClaims(jwtString, &sessionClaims{}, func(t *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("JWT_SECRET")), nil
	})
	if err != nil {
		return AuthSession{}, err
	} else if claims, ok := token.Claims.(*sessionClaims); ok {
		issuer := claims.Issuer
		if issuer != os.Getenv("JWT_ISSUER") {
			return AuthSession{}, errors.New("Invalid JWT. Issuer.")
		}
		expiresAt := claims.ExpiresAt
		if expiresAt.Before(time.Now()) {
			return AuthSession{}, errors.New("Invalid JWT. Expired.")
		}
		issuedAt := claims.IssuedAt
		if !expiresAt.Equal(issuedAt.Add(24 * time.Hour)) {
			return AuthSession{}, errors.New("Invalid JWT.")
		}

		return claims.Session, nil
	} else {
		return AuthSession{}, errors.New("Invalid JWT claims type")
	}
}

type AuthOwner struct {
	Id   int    `json:"id"`
	Name string `json:"name"`
}

type ownerClaims struct {
	Owner AuthOwner `json:"owner"`
	jwt.RegisteredClaims
}

func SignAuthOwner(owner AuthOwner) (string, error) {
	now := time.Now()
	claims := ownerClaims{
		owner,
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(100 * 365 * 24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
			Issuer:    os.Getenv("JWT_ISSUER"),
		},
	}

	return sign(claims)
}

func ParseOwnerJWT(jwtString string) (AuthOwner, error) {
	token, err := jwt.ParseWithClaims(jwtString, &ownerClaims{}, func(t *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("JWT_SECRET")), nil
	})
	if err != nil {
		return AuthOwner{}, err
	} else if claims, ok := token.Claims.(*ownerClaims); ok {
		issuer := claims.Issuer
		if issuer != os.Getenv("JWT_ISSUER") {
			return AuthOwner{}, errors.New("Invalid JWT. Issuer.")
		}
		expiresAt := claims.ExpiresAt
		if expiresAt.Before(time.Now()) {
			return AuthOwner{}, errors.New("Invalid JWT. Expired.")
		}
		issuedAt := claims.IssuedAt
		if issuedAt.After(time.Now()) {
			return AuthOwner{}, errors.New("Invalid JWT. Issued at.")
		}

		return claims.Owner, nil
	} else {
		return AuthOwner{}, errors.New("Invalid JWT claims type")
	}
}

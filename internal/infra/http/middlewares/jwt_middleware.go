package middlewares

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/Wonbet/medods/internal/domain/auth/service"
	http2 "github.com/Wonbet/medods/pkg/http"
	"github.com/google/uuid"
)

type AuthService interface {
	ValidateAccessToken(tokenString string) (uuid.UUID, error)
	IsUserLoggedOut(userID uuid.UUID) bool
}

type JWTAuthMiddleware struct {
	next        http.Handler
	authService AuthService
	publicPaths map[string]bool
}

func NewJWTAuthMiddleware(next http.Handler, authService AuthService) http.Handler {
	return &JWTAuthMiddleware{
		next:        next,
		authService: authService,
		publicPaths: map[string]bool{
			"GET /auth/token/":   true,
			"POST /auth/refresh": true,
			"GET /health":        true,
		},
	}
}

func (m *JWTAuthMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if m.isPublicPath(r.Method, r.URL.Path) {
		m.next.ServeHTTP(w, r)
		return
	}

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		if err := http2.ErrorResponse(w, http.StatusUnauthorized, "Authorization header is required"); err != nil {
			fmt.Println("json.Encode failed ", err)
			return
		}
		return
	}

	tokenParts := strings.Split(authHeader, " ")
	if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
		if err := http2.ErrorResponse(w, http.StatusUnauthorized, "Invalid authorization format"); err != nil {
			fmt.Println("json.Encode failed ", err)
			return
		}
		return
	}

	userID, err := m.authService.ValidateAccessToken(tokenParts[1])
	if err != nil {
		statusCode := http.StatusUnauthorized
		message := "Invalid token"

		if err == service.ErrTokenExpired {
			message = "Token expired"
		}

		if err := http2.ErrorResponse(w, statusCode, message); err != nil {
			fmt.Println("json.Encode failed ", err)
			return
		}
		return
	}

	if m.authService.IsUserLoggedOut(userID) {
		if err := http2.ErrorResponse(w, http.StatusUnauthorized, "User is logged out"); err != nil {
			fmt.Println("json.Encode failed ", err)
			return
		}
		return
	}

	ctx := context.WithValue(r.Context(), "user_id", userID)
	r = r.WithContext(ctx)

	m.next.ServeHTTP(w, r)
}

func (m *JWTAuthMiddleware) isPublicPath(method, path string) bool {
	if m.publicPaths[method+" "+path] {
		return true
	}

	for publicPath := range m.publicPaths {
		parts := strings.Split(publicPath, " ")
		if len(parts) == 2 && parts[0] == method {
			if strings.HasSuffix(parts[1], "/") && strings.HasPrefix(path, parts[1]) {
				return true
			}
		}
	}

	return false
}

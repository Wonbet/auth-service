package refresh_handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/Wonbet/medods/internal/domain/auth/service"
	"github.com/Wonbet/medods/internal/domain/model"
	http2 "github.com/Wonbet/medods/pkg/http"
)

type AuthService interface {
	RefreshTokens(ctx context.Context, refreshToken string, userAgent string, ip string) (model.TokenPair, error)
}

type RefreshHandler struct {
	authService AuthService
}

func NewRefreshHandler(authService AuthService) *RefreshHandler {
	return &RefreshHandler{authService: authService}
}

func (h *RefreshHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	var request RefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		if err = http2.ErrorResponse(w, http.StatusBadRequest, "Invalid request format"); err != nil {
			fmt.Println("json.Encode failed ", err)
			return
		}
		return
	}

	userAgent := r.UserAgent()
	ip := http2.GetClientIP(r)

	tokenPair, err := h.authService.RefreshTokens(r.Context(), request.RefreshToken, userAgent, ip)
	if err != nil {
		statusCode := http.StatusInternalServerError
		message := err.Error()

		if err == service.ErrInvalidToken {
			statusCode = http.StatusUnauthorized
			message = "Invalid refresh token"
		} else if err == service.ErrUserAgentMismatch {
			statusCode = http.StatusUnauthorized
			message = "User agent mismatch, you have been logged out"
		}

		if err = http2.ErrorResponse(w, statusCode, message); err != nil {
			fmt.Println("json.Encode failed ", err)
			return
		}
		return
	}

	response := RefreshResponse{
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
	}

	if err := http2.SuccessResponse(w, http.StatusOK, response); err != nil {
		fmt.Println("json.Encode failed ", err)
		return
	}
}
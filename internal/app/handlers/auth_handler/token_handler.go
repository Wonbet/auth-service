package auth_handler

import (
	"context"
	"fmt"
	"net/http"

	"github.com/Wonbet/medods/internal/domain/model"
	http2 "github.com/Wonbet/medods/pkg/http"
	"github.com/google/uuid"
)

type AuthService interface {
	GenerateTokenPair(ctx context.Context, userID uuid.UUID, userAgent string, ip string) (model.TokenPair, error)
}

type TokenHandler struct {
	authService AuthService
}

func NewTokenHandler(authService AuthService) *TokenHandler {
	return &TokenHandler{authService: authService}
}

func (h *TokenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	userIDParam := r.PathValue("user_id")
	userID, err := uuid.Parse(userIDParam)
	if err != nil {
		if err = http2.ErrorResponse(w, http.StatusBadRequest, "Invalid user ID format"); err != nil {
			fmt.Println("json.Encode failed ", err)
			return
		}
		return
	}

	userAgent := r.UserAgent()
	ip := http2.GetClientIP(r)

	tokenPair, err := h.authService.GenerateTokenPair(r.Context(), userID, userAgent, ip)
	if err != nil {
		if err = http2.ErrorResponse(w, http.StatusInternalServerError, err.Error()); err != nil {
			fmt.Println("json.Encode failed ", err)
			return
		}
		return
	}

	response := TokenResponse{
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
	}

	if err := http2.SuccessResponse(w, http.StatusOK, response); err != nil {
		fmt.Println("json.Encode failed ", err)
		return
	}
}

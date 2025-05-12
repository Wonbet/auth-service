package user_handler

import (
	"context"
	"fmt"
	"net/http"

	http2 "github.com/Wonbet/medods/pkg/http"
	"github.com/google/uuid"
)

type LogoutService interface {
	Logout(ctx context.Context, userID uuid.UUID) error
}

type LogoutHandler struct {
	authService LogoutService
}

func NewLogoutHandler(authService LogoutService) *LogoutHandler {
	return &LogoutHandler{authService: authService}
}

func (h *LogoutHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value("user_id").(uuid.UUID)
	if !ok {
		if err := http2.ErrorResponse(w, http.StatusUnauthorized, "Unauthorized"); err != nil {
			fmt.Println("json.Encode failed ", err)
			return
		}
		return
	}

	if err := h.authService.Logout(r.Context(), userID); err != nil {
		if err := http2.ErrorResponse(w, http.StatusInternalServerError, err.Error()); err != nil {
			fmt.Println("json.Encode failed ", err)
			return
		}
		return
	}

	if err := http2.SuccessResponse(w, http.StatusOK, LogoutResponse{Success: true}); err != nil {
		fmt.Println("json.Encode failed ", err)
		return
	}
}

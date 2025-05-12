package user_handler

import (
	"context"
	"fmt"
	"net/http"

	"github.com/Wonbet/medods/internal/domain/model"
	http2 "github.com/Wonbet/medods/pkg/http"
	"github.com/google/uuid"
)

type AuthService interface {
	GetUserByID(ctx context.Context, userID uuid.UUID) (model.User, error)
}

type UserHandler struct {
	authService AuthService
}

func NewUserHandler(authService AuthService) *UserHandler {
	return &UserHandler{authService: authService}
}

func (h *UserHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value("user_id").(uuid.UUID)
	if !ok {
		if err := http2.ErrorResponse(w, http.StatusUnauthorized, "Unauthorized"); err != nil {
			fmt.Println("json.Encode failed ", err)
			return
		}
		return
	}

	user, err := h.authService.GetUserByID(r.Context(), userID)
	if err != nil {
		if err := http2.ErrorResponse(w, http.StatusInternalServerError, err.Error()); err != nil {
			fmt.Println("json.Encode failed ", err)
			return
		}
		return
	}

	response := UserResponse{
		UserID: user.ID.String(),
	}

	if err := http2.SuccessResponse(w, http.StatusOK, response); err != nil {
		fmt.Println("json.Encode failed ", err)
		return
	}
}

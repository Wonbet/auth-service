package model

import (
	"time"

	"github.com/google/uuid"
)

type TokenPair struct {
	AccessToken  string
	RefreshToken string
}

type RefreshTokenData struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	TokenHash string
	UserAgent string
	IP        string
	Used      bool
	ExpiresAt time.Time
	CreatedAt time.Time
}
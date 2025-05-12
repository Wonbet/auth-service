package model

import (
	"time"

	"github.com/google/uuid"
)

type Session struct {
	ID          uuid.UUID
	UserID      uuid.UUID
	RefreshHash string
	UserAgent   string
	IP          string
	JTI         uuid.UUID
	ExpiresAt   time.Time
	IsRevoked   bool
}

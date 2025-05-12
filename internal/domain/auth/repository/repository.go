package repository

import (
	"context"
	"errors"
	"time"

	"github.com/Wonbet/medods/internal/domain/model"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrTokenNotFound      = errors.New("refresh token not found")
	ErrTokenAlreadyUsed   = errors.New("refresh token already used")
	ErrInvalidCredentials = errors.New("invalid credentials")
)

type AuthRepository struct {
	db *pgxpool.Pool
}

func NewAuthRepository(db *pgxpool.Pool) *AuthRepository {
	return &AuthRepository{
		db: db,
	}
}

func (r *AuthRepository) SaveRefreshToken(ctx context.Context, tokenData model.RefreshTokenData) error {
	query := `
		INSERT INTO refresh_tokens (id, user_id, token_hash, user_agent, ip, used, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`

	_, err := r.db.Exec(ctx, query,
		tokenData.ID,
		tokenData.UserID,
		tokenData.TokenHash,
		tokenData.UserAgent,
		tokenData.IP,
		tokenData.Used,
		tokenData.ExpiresAt,
		tokenData.CreatedAt,
	)

	return err
}

func (r *AuthRepository) GetRefreshToken(ctx context.Context, tokenID uuid.UUID) (model.RefreshTokenData, error) {
	query := `
		SELECT id, user_id, token_hash, user_agent, ip, used, expires_at, created_at
		FROM refresh_tokens
		WHERE id = $1 AND used = false AND expires_at > $2
	`

	var token model.RefreshTokenData
	err := r.db.QueryRow(ctx, query, tokenID, time.Now()).Scan(
		&token.ID,
		&token.UserID,
		&token.TokenHash,
		&token.UserAgent,
		&token.IP,
		&token.Used,
		&token.ExpiresAt,
		&token.CreatedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return model.RefreshTokenData{}, ErrTokenNotFound
		}
		return model.RefreshTokenData{}, err
	}

	return token, nil
}

func (r *AuthRepository) InvalidateRefreshToken(ctx context.Context, tokenID uuid.UUID) error {
	query := `
		UPDATE refresh_tokens
		SET used = true
		WHERE id = $1
	`

	_, err := r.db.Exec(ctx, query, tokenID)
	return err
}

func (r *AuthRepository) InvalidateAllUserTokens(ctx context.Context, userID uuid.UUID) error {
	query := `
		UPDATE refresh_tokens
		SET used = true
		WHERE user_id = $1
	`

	_, err := r.db.Exec(ctx, query, userID)
	return err
}

func (r *AuthRepository) VerifyRefreshToken(ctx context.Context, tokenHash string, providedToken string) error {
	err := bcrypt.CompareHashAndPassword([]byte(tokenHash), []byte(providedToken))
	if err != nil {
		return ErrInvalidCredentials
	}
	return nil
}
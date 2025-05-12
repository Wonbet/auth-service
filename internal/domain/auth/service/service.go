package service

import (
	"context"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Wonbet/medods/internal/domain/auth/repository"
	"github.com/Wonbet/medods/internal/domain/model"
	"github.com/Wonbet/medods/internal/infra/config"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidToken      = errors.New("invalid token")
	ErrTokenExpired      = errors.New("token expired")
	ErrUserAgentMismatch = errors.New("user agent mismatch")
)

type AuthRepository interface {
	SaveRefreshToken(ctx context.Context, tokenData model.RefreshTokenData) error
	GetRefreshToken(ctx context.Context, tokenID uuid.UUID) (model.RefreshTokenData, error)
	InvalidateRefreshToken(ctx context.Context, tokenID uuid.UUID) error
	InvalidateAllUserTokens(ctx context.Context, userID uuid.UUID) error
	VerifyRefreshToken(ctx context.Context, tokenHash string, providedToken string) error
}

type WebhookClient interface {
	NotifyNewIP(userID uuid.UUID, oldIP, newIP string) error
}

type AuthService struct {
	repo           AuthRepository
	webhookClient  WebhookClient
	config         *config.Config
	loggedOutUsers sync.Map
}

func NewAuthService(repo AuthRepository, webhookClient WebhookClient, config *config.Config) *AuthService {
	return &AuthService{
		repo:           repo,
		webhookClient:  webhookClient,
		config:         config,
		loggedOutUsers: sync.Map{},
	}
}

func (s *AuthService) GenerateTokenPair(ctx context.Context, userID uuid.UUID, userAgent string, ip string) (model.TokenPair, error) {
	accessToken, err := s.generateAccessToken(userID)
	if err != nil {
		return model.TokenPair{}, fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshTokenID := uuid.New()
	refreshToken, refreshTokenHash, err := s.generateRefreshToken()
	if err != nil {
		return model.TokenPair{}, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	tokenData := model.RefreshTokenData{
		ID:        refreshTokenID,
		UserID:    userID,
		TokenHash: refreshTokenHash,
		UserAgent: userAgent,
		IP:        ip,
		Used:      false,
		ExpiresAt: time.Now().Add(time.Duration(s.config.Auth.RefreshTokenTTL) * time.Second),
		CreatedAt: time.Now(),
	}

	if err := s.repo.SaveRefreshToken(ctx, tokenData); err != nil {
		return model.TokenPair{}, fmt.Errorf("failed to save refresh token: %w", err)
	}

	s.loggedOutUsers.Delete(userID)

	signedRefreshToken := s.signRefreshToken(refreshTokenID.String(), refreshToken)
	encodedRefreshToken := base64.StdEncoding.EncodeToString([]byte(signedRefreshToken))

	return model.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: encodedRefreshToken,
	}, nil
}

func (s *AuthService) RefreshTokens(ctx context.Context, refreshToken string, userAgent string, ip string) (model.TokenPair, error) {
	decodedToken, err := base64.StdEncoding.DecodeString(refreshToken)
	if err != nil {
		return model.TokenPair{}, ErrInvalidToken
	}

	tokenID, token, err := s.parseAndVerifyRefreshToken(string(decodedToken))
	if err != nil {
		return model.TokenPair{}, err
	}

	tokenUUID, err := uuid.Parse(tokenID)
	if err != nil {
		return model.TokenPair{}, ErrInvalidToken
	}

	tokenData, err := s.repo.GetRefreshToken(ctx, tokenUUID)
	if err != nil {
		if errors.Is(err, repository.ErrTokenNotFound) {
			return model.TokenPair{}, ErrInvalidToken
		}
		return model.TokenPair{}, err
	}

	if s.IsUserLoggedOut(tokenData.UserID) {
		return model.TokenPair{}, ErrInvalidToken
	}

	if tokenData.UserAgent != userAgent {
		if err := s.repo.InvalidateAllUserTokens(ctx, tokenData.UserID); err != nil {
			return model.TokenPair{}, err
		}
		s.loggedOutUsers.Store(tokenData.UserID, true)
		return model.TokenPair{}, ErrUserAgentMismatch
	}

	if tokenData.IP != ip {
		if err := s.webhookClient.NotifyNewIP(tokenData.UserID, tokenData.IP, ip); err != nil {
			fmt.Printf("Failed to notify about IP change: %v\n", err)
		}
	}

	if err := s.repo.VerifyRefreshToken(ctx, tokenData.TokenHash, token); err != nil {
		return model.TokenPair{}, err
	}

	if err := s.repo.InvalidateRefreshToken(ctx, tokenUUID); err != nil {
		return model.TokenPair{}, err
	}

	return s.GenerateTokenPair(ctx, tokenData.UserID, userAgent, ip)
}

func (s *AuthService) ValidateAccessToken(tokenString string) (uuid.UUID, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.config.Auth.JWTSecret), nil
	})

	if err != nil {
		return uuid.Nil, ErrInvalidToken
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		userID, ok := claims["sub"].(string)
		if !ok {
			return uuid.Nil, ErrInvalidToken
		}

		userUUID, err := uuid.Parse(userID)
		if err != nil {
			return uuid.Nil, ErrInvalidToken
		}

		return userUUID, nil
	}

	return uuid.Nil, ErrInvalidToken
}

func (s *AuthService) Logout(ctx context.Context, userID uuid.UUID) error {
	if err := s.repo.InvalidateAllUserTokens(ctx, userID); err != nil {
		return err
	}

	s.loggedOutUsers.Store(userID, true)

	return nil
}

func (s *AuthService) IsUserLoggedOut(userID uuid.UUID) bool {
	_, ok := s.loggedOutUsers.Load(userID)
	return ok
}

func (s *AuthService) generateAccessToken(userID uuid.UUID) (string, error) {
	claims := jwt.MapClaims{
		"sub": userID.String(),
		"exp": time.Now().Add(time.Duration(s.config.Auth.AccessTokenTTL) * time.Second).Unix(),
		"iat": time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	return token.SignedString([]byte(s.config.Auth.JWTSecret))
}

func (s *AuthService) generateRefreshToken() (string, string, error) {
	tokenBytes := make([]byte, 32)
	_, err := uuid.New().MarshalBinary()
	if err != nil {
		return "", "", err
	}
	token := hex.EncodeToString(tokenBytes)

	hashedToken, err := bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
	if err != nil {
		return "", "", err
	}

	return token, string(hashedToken), nil
}

func (s *AuthService) signRefreshToken(tokenID, token string) string {
	data := tokenID + "." + token
	h := hmac.New(sha512.New, []byte(s.config.Auth.RefreshTokenSecret))
	h.Write([]byte(data))
	signature := hex.EncodeToString(h.Sum(nil))
	return data + "." + signature
}

func (s *AuthService) parseAndVerifyRefreshToken(signedToken string) (string, string, error) {
	tokenParts := strings.Split(signedToken, ".")
	if len(tokenParts) != 3 {
		return "", "", ErrInvalidToken
	}

	tokenID := tokenParts[0]
	token := tokenParts[1]
	providedSignature := tokenParts[2]

	data := tokenID + "." + token
	h := hmac.New(sha512.New, []byte(s.config.Auth.RefreshTokenSecret))
	h.Write([]byte(data))
	expectedSignature := hex.EncodeToString(h.Sum(nil))

	if providedSignature != expectedSignature {
		return "", "", ErrInvalidToken
	}

	return tokenID, token, nil
}

func (s *AuthService) GetUserByID(ctx context.Context, userID uuid.UUID) (model.User, error) {
	return model.User{ID: userID}, nil
}

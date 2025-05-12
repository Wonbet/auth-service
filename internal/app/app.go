package app

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/Wonbet/medods/internal/app/handlers/auth_handler"
	"github.com/Wonbet/medods/internal/app/handlers/health_handler"
	"github.com/Wonbet/medods/internal/app/handlers/refresh_handler"
	"github.com/Wonbet/medods/internal/app/handlers/user_handler"
	"github.com/Wonbet/medods/internal/domain/auth/repository"
	"github.com/Wonbet/medods/internal/domain/auth/service"
	"github.com/Wonbet/medods/internal/infra/config"
	"github.com/Wonbet/medods/internal/infra/http/middlewares"
	"github.com/Wonbet/medods/internal/infra/webhook"
	"github.com/jackc/pgx/v5/pgxpool"
)

const Version = "1.0.0"

type App struct {
	config *config.Config
	server http.Server
	db     *pgxpool.Pool
}

func NewApp(configPath string) (*App, error) {
	configImpl, err := config.LoadConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("config.LoadConfig: %w", err)
	}

	db, err := pgxpool.New(context.Background(), configImpl.Database.DSN)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	app := &App{
		config: configImpl,
		db:     db,
	}

	app.server.Handler = bootstrapHandler(configImpl, db)

	return app, nil
}

func (app *App) CheckDBConnection() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return app.db.Ping(ctx)
}

func (app *App) GetHost() string {
	return app.config.Server.Host
}

func (app *App) GetPort() string {
	return app.config.Server.Port
}

func (app *App) ListenAndServe() error {
	address := fmt.Sprintf("%s:%s", app.config.Server.Host, app.config.Server.Port)

	l, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}

	return app.server.Serve(l)
}

func (app *App) Shutdown(ctx context.Context) error {
	app.db.Close()

	return app.server.Shutdown(ctx)
}

func bootstrapHandler(config *config.Config, db *pgxpool.Pool) http.Handler {
	authRepository := repository.NewAuthRepository(db)

	webhookClient := webhook.NewWebhookClient(config.Auth.WebhookURL, config.Auth.AllowedHosts)

	authService := service.NewAuthService(authRepository, webhookClient, config)

	mx := http.NewServeMux()
	mx.Handle("GET /auth/token/{user_id}", auth_handler.NewTokenHandler(authService))
	mx.Handle("POST /auth/refresh", refresh_handler.NewRefreshHandler(authService))
	mx.Handle("GET /auth/me", user_handler.NewUserHandler(authService))
	mx.Handle("POST /auth/logout", user_handler.NewLogoutHandler(authService))

	mx.Handle("GET /health", health_handler.NewHealthHandler(Version))

	middleware := middlewares.NewJWTAuthMiddleware(mx, authService)

	return middleware
}

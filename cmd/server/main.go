package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	app2 "github.com/Wonbet/medods/internal/app"
	"github.com/joho/godotenv"
)

func main() {
	fmt.Println("Auth service starting...")

	if err := godotenv.Load(); err != nil {
		log.Println("Warning: .env file not found or cannot be loaded")
	} else {
		fmt.Println("Environment variables loaded from .env file")
	}

	configPath := os.Getenv("CONFIG_PATH")
	if configPath == "" {
		configPath = "./configs/values_prod.yaml"
	}

	fmt.Printf("Using config from: %s\n", configPath)

	app, err := app2.NewApp(configPath)
	if err != nil {
		log.Fatalf("Failed to initialize app: %v", err)
	}

	if err := app.CheckDBConnection(); err != nil {
		log.Fatalf("Database connection check failed: %v", err)
	}
	fmt.Println("Successfully connected to database")

	go func() {
		fmt.Printf("Starting HTTP server on %s:%s\n", app.GetHost(), app.GetPort())
		if err := app.ListenAndServe(); err != nil {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	fmt.Println("Auth service started successfully")

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	fmt.Println("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := app.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	fmt.Println("Server exited properly")
}

package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	fiberlog "github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/siliconsignals/vms/backend/internal/auth"
	"github.com/siliconsignals/vms/backend/internal/config"
	appcrypto "github.com/siliconsignals/vms/backend/internal/crypto"
	"github.com/siliconsignals/vms/backend/internal/go2rtc"
	"github.com/siliconsignals/vms/backend/internal/recording"
)

func main() {
	cfg := config.Load()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	dbPool, err := connectPostgres(ctx, cfg)
	if err != nil {
		log.Fatalf("postgres: %v", err)
	}
	defer dbPool.Close()

	redisClient := redis.NewClient(&redis.Options{
		Addr:     cfg.RedisAddr(),
		Password: cfg.RedisPassword,
		DB:       cfg.RedisDB,
	})
	defer redisClient.Close()

	if err := redisClient.Ping(ctx).Err(); err != nil {
		log.Fatalf("redis: %v", err)
	}

	jwtIssuer, err := auth.NewJWTIssuer(cfg.JWTPrivateKeyPath, cfg.JWTPublicKeyPath, cfg.JWTIssuer, cfg.JWTAccessTokenTTL)
	if err != nil {
		log.Fatalf("auth: %v", err)
	}

	credKey, err := appcrypto.ParseKeyHex(cfg.CameraCredentialsEncKey)
	if err != nil {
		log.Fatalf("camera credentials key: %v", err)
	}

	hlsKey, err := appcrypto.ParseKeyHex(cfg.HLSTokenSecret)
	if err != nil {
		log.Fatalf("hls token secret: %v", err)
	}

	go2rtcClient := go2rtc.NewClient(cfg.GO2RTCHost, cfg.GO2RTCAPIPort)
	reconcileGo2RTCStreams(ctx, dbPool, go2rtcClient, credKey)

	segWatch, err := recording.NewSegmentWatcher(dbPool, cfg.RecordingStoragePath, time.Duration(cfg.RecordingSegmentDurationSec)*time.Second)
	if err != nil {
		log.Fatalf("recording: %v", err)
	}
	go segWatch.Run(ctx)

	recMgr := recording.NewManager(dbPool, cfg.RecordingStoragePath, cfg.RecordingSegmentDurationSec, cfg.RecordingFFmpegLogLevel, cfg.RecordingReconcileInterval, credKey, segWatch)
	go recMgr.Run(ctx)
	go recording.RunRetentionSweep(ctx, dbPool, cfg.RecordingRetentionSweepInterval, cfg.RecordingStoragePath)

	app := fiber.New(fiber.Config{
		AppName:               "vms-backend",
		DisableStartupMessage: cfg.AppEnv == "production",
		ReadTimeout:           15 * time.Second,
		WriteTimeout:          15 * time.Second,
	})

	app.Use(recover.New())
	app.Use(fiberlog.New())
	app.Use(cors.New(cors.Config{
		AllowOrigins:     joinOrDefault(cfg.CORSAllowedOrigins, "*"),
		AllowCredentials: len(cfg.CORSAllowedOrigins) > 0,
	}))

	registerHealthRoutes(app, dbPool, redisClient)
	registerInternalRoutes(app, hlsKey[:])

	api := app.Group("/api/v1")
	registerV1Routes(api)
	registerAuthRoutes(api.Group("/auth"), dbPool, jwtIssuer, cfg)
	registerCameraRoutes(api, dbPool, jwtIssuer, go2rtcClient, credKey, cfg, recMgr)
	registerRecordingRoutes(api, dbPool, jwtIssuer, hlsKey[:], cfg.HLSTokenTTL, recMgr)

	go func() {
		addr := cfg.APIHost + ":" + cfg.APIPort
		log.Printf("vms-backend listening on %s (env=%s)", addr, cfg.AppEnv)
		if err := app.Listen(addr); err != nil {
			log.Fatalf("fiber: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("shutdown signal received, draining connections...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := app.ShutdownWithContext(shutdownCtx); err != nil {
		log.Printf("shutdown: %v", err)
	}
}

func connectPostgres(ctx context.Context, cfg config.Config) (*pgxpool.Pool, error) {
	poolCfg, err := pgxpool.ParseConfig(cfg.DatabaseURL)
	if err != nil {
		return nil, err
	}
	poolCfg.MaxConns = int32(cfg.PostgresMaxOpenConn)
	poolCfg.MinConns = int32(cfg.PostgresMaxIdleConn)
	poolCfg.MaxConnLifetime = cfg.PostgresConnMaxLife

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return pool, nil
}

func joinOrDefault(origins []string, fallback string) string {
	if len(origins) == 0 {
		return fallback
	}
	out := origins[0]
	for _, o := range origins[1:] {
		out += "," + o
	}
	return out
}

// Package config loads runtime configuration from environment variables.
// See .env.example at the repo root for the full, documented list.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	AppEnv   string
	LogLevel string

	APIHost string
	APIPort string

	DatabaseURL         string
	PostgresMaxOpenConn int
	PostgresMaxIdleConn int
	PostgresConnMaxLife time.Duration

	RedisHost     string
	RedisPort     string
	RedisPassword string
	RedisDB       int

	JWTPrivateKeyPath   string
	JWTPublicKeyPath    string
	JWTIssuer           string
	JWTAccessTokenTTL   time.Duration
	JWTRefreshTokenTTL  time.Duration
	JWTRefreshRotate    bool

	CameraCredentialsEncKey string
	HLSTokenSecret          string
	HLSTokenTTL             time.Duration

	GO2RTCHost    string
	GO2RTCAPIPort string

	CORSAllowedOrigins []string
}

// Load reads configuration from the process environment. It panics on a
// malformed value (bad int/bool/duration) since that indicates a broken
// deployment, not a recoverable runtime condition.
func Load() Config {
	return Config{
		AppEnv:   getEnv("APP_ENV", "development"),
		LogLevel: getEnv("LOG_LEVEL", "info"),

		APIHost: getEnv("API_HOST", "0.0.0.0"),
		APIPort: getEnv("API_PORT", "8080"),

		DatabaseURL:         mustEnv("DATABASE_URL"),
		PostgresMaxOpenConn: getEnvInt("POSTGRES_MAX_OPEN_CONNS", 25),
		PostgresMaxIdleConn: getEnvInt("POSTGRES_MAX_IDLE_CONNS", 5),
		PostgresConnMaxLife: time.Duration(getEnvInt("POSTGRES_CONN_MAX_LIFETIME_MIN", 30)) * time.Minute,

		RedisHost:     getEnv("REDIS_HOST", "redis"),
		RedisPort:     getEnv("REDIS_PORT", "6379"),
		RedisPassword: getEnv("REDIS_PASSWORD", ""),
		RedisDB:       getEnvInt("REDIS_DB", 0),

		JWTPrivateKeyPath:  getEnv("JWT_PRIVATE_KEY_PATH", ""),
		JWTPublicKeyPath:   getEnv("JWT_PUBLIC_KEY_PATH", ""),
		JWTIssuer:          getEnv("JWT_ISSUER", "vms-platform"),
		JWTAccessTokenTTL:  time.Duration(getEnvInt("JWT_ACCESS_TOKEN_TTL_MIN", 15)) * time.Minute,
		JWTRefreshTokenTTL: time.Duration(getEnvInt("JWT_REFRESH_TOKEN_TTL_DAYS", 7)) * 24 * time.Hour,
		JWTRefreshRotate:   getEnvBool("JWT_REFRESH_TOKEN_ROTATE", true),

		CameraCredentialsEncKey: getEnv("CAMERA_CREDENTIALS_ENC_KEY", ""),
		HLSTokenSecret:          getEnv("HLS_TOKEN_SECRET", ""),
		HLSTokenTTL:             time.Duration(getEnvInt("HLS_TOKEN_TTL_SEC", 30)) * time.Second,

		GO2RTCHost:    getEnv("GO2RTC_HOST", "go2rtc"),
		GO2RTCAPIPort: getEnv("GO2RTC_API_PORT", "1984"),

		CORSAllowedOrigins: splitCSV(getEnv("CORS_ALLOWED_ORIGINS", "")),
	}
}

// RedisAddr returns the host:port form expected by go-redis.
func (c Config) RedisAddr() string {
	return fmt.Sprintf("%s:%s", c.RedisHost, c.RedisPort)
}

func getEnv(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}

func mustEnv(key string) string {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		panic(fmt.Sprintf("config: required environment variable %s is not set", key))
	}
	return v
}

func getEnvInt(key string, fallback int) int {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		panic(fmt.Sprintf("config: %s must be an integer, got %q", key, v))
	}
	return n
}

func getEnvBool(key string, fallback bool) bool {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return fallback
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		panic(fmt.Sprintf("config: %s must be a bool, got %q", key, v))
	}
	return b
}

func splitCSV(v string) []string {
	if v == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

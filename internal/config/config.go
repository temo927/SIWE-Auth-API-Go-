package config

import (
	"fmt"
	"os"
	"strings"
	"time"
)

type Config struct {
	AppName        string
	Env            string
	HTTPAddr       string
	AllowedOrigins []string
	TokenIssuer    string
	TokenAudience  string
	AccessTTL      time.Duration
	RefreshTTL     time.Duration
	JWTKey         []byte
	SIWEDomain     string
	SIWEURI        string
	ChainIDs       map[uint64]struct{}
	StoreBackend   string
	RedisAddr      string
	RedisDB        int
}

func mustParseDuration(s, name string) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil {
		panic(fmt.Errorf("%s: %w", name, err))
	}
	return d
}

func parseChainIDs(s string) map[uint64]struct{} {
	m := make(map[uint64]struct{})
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		var v uint64
		_, err := fmt.Sscanf(p, "%d", &v)
		if err == nil {
			m[v] = struct{}{}
		}
	}
	return m
}

func Load() (*Config, error) {
	c := &Config{
		AppName:        get("APP_NAME", "siwe-auth"),
		Env:            get("APP_ENV", "dev"),
		HTTPAddr:       get("HTTP_ADDR", ":8080"),
		AllowedOrigins: strings.Split(get("ALLOWED_ORIGINS", "http://localhost:3000"), ","),
		TokenIssuer:    get("TOKEN_ISSUER", "siwe-auth"),
		TokenAudience:  get("TOKEN_AUDIENCE", "http://localhost:8080"),
		AccessTTL:      mustParseDuration(get("ACCESS_TOKEN_TTL", "15m"), "ACCESS_TOKEN_TTL"),
		RefreshTTL:     mustParseDuration(get("REFRESH_TOKEN_TTL", "720h"), "REFRESH_TOKEN_TTL"),
		JWTKey:         []byte(get("JWT_SIGNING_KEY", "change-me")),
		SIWEDomain:     get("SIWE_DOMAIN", "localhost"),
		SIWEURI:        get("SIWE_URI", "http://localhost:3000"),
		ChainIDs:       parseChainIDs(get("SIWE_ALLOWED_CHAIN_IDS", "1")),
		StoreBackend:   get("STORE_BACKEND", "memory"),
		RedisAddr:      get("REDIS_ADDR", "localhost:6379"),
	}
	return c, nil
}

func get(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

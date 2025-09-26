package httpx

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/rs/cors"
	"github.com/temo927/SIWE-Auth-API-Go-/internal/auth"
	"github.com/temo927/SIWE-Auth-API-Go-/internal/config"
	"github.com/temo927/SIWE-Auth-API-Go-/internal/session"
	"github.com/temo927/SIWE-Auth-API-Go-/internal/store"
)

type Router struct{ http.Handler }

func NewRouter(cfg *config.Config) http.Handler {
	var st store.Store
	if strings.EqualFold(cfg.StoreBackend, "redis") {
		st = store.NewRedisStore(cfg)
	} else {
		st = store.NewMemoryStore()
	}
	jwt := session.NewJWT(cfg)
	svc := auth.NewService(cfg, st, jwt)

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/v1/auth/nonce", jsonHandler(svc.HandleNonce))
	mux.HandleFunc("/v1/auth/siwe/prepare", jsonHandler(svc.HandlePrepare))
	mux.HandleFunc("/v1/auth/verify", jsonHandler(svc.HandleVerify))
	mux.HandleFunc("/v1/me", jwt.AuthRequired(jsonHandler(svc.HandleMe)))
	mux.HandleFunc("/v1/auth/logout", jwt.AuthRequired(jsonHandler(svc.HandleLogout)))

	c := cors.New(cors.Options{
		AllowedOrigins:   cfg.AllowedOrigins,
		AllowCredentials: true,
		AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type", "Authorization"},
	})
	return c.Handler(logging(mux))
}

func logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

func jsonHandler(fn func(http.ResponseWriter, *http.Request) (any, int, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		res, code, err := fn(w, r)
		if err != nil {
			w.WriteHeader(code)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		if res != nil {
			_ = json.NewEncoder(w).Encode(res)
		}
	}
}

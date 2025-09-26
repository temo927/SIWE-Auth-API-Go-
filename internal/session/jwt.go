package session

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/temo927/SIWE-Auth-API-Go-/internal/config"
)

type JWT struct{ cfg *config.Config }

func NewJWT(cfg *config.Config) *JWT { return &JWT{cfg: cfg} }

type Claims struct {
	Addr string `json:"addr"`
	jwt.RegisteredClaims
}

func (j *JWT) Mint(address string) (string, time.Time, error) {
	exp := time.Now().Add(j.cfg.AccessTTL)
	c := Claims{Addr: address, RegisteredClaims: jwt.RegisteredClaims{Issuer: j.cfg.TokenIssuer, Audience: jwt.ClaimStrings{j.cfg.TokenAudience}, IssuedAt: jwt.NewNumericDate(time.Now()), ExpiresAt: jwt.NewNumericDate(exp)}}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
	s, err := tok.SignedString(j.cfg.JWTKey)
	return s, exp, err
}

func (j *JWT) Parse(token string) (*Claims, error) {
	parsed, err := jwt.ParseWithClaims(token, &Claims{}, func(t *jwt.Token) (any, error) { return j.cfg.JWTKey, nil })
	if err != nil {
		return nil, err
	}
	c, ok := parsed.Claims.(*Claims)
	if !ok || !parsed.Valid {
		return nil, errors.New("invalid token")
	}
	return c, nil
}

func (j *JWT) AuthRequired(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		bearer := r.Header.Get("Authorization")
		if !strings.HasPrefix(bearer, "Bearer ") {
			http.Error(w, "missing token", http.StatusUnauthorized)
			return
		}
		tok := strings.TrimPrefix(bearer, "Bearer ")
		c, err := j.Parse(tok)
		if err != nil {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		r = r.WithContext(withAddr(r.Context(), c.Addr))
		next(w, r)
	}
}

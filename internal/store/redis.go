package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/temo927/SIWE-Auth-API-Go-/internal/config"
)

type redisStore struct{ rdb *redis.Client }

func NewRedisStore(cfg *config.Config) Store {
	return &redisStore{rdb: redis.NewClient(&redis.Options{Addr: cfg.RedisAddr, DB: cfg.RedisDB})}
}

func (s *redisStore) PutNonce(n Nonce) {
	b, _ := json.Marshal(n)
	s.rdb.Set(context.Background(), "siwe:nonce:"+n.Value, b, time.Until(n.Exp))
}

func (s *redisStore) GetNonce(v string) (Nonce, bool) {
	b, err := s.rdb.Get(context.Background(), "siwe:nonce:"+v).Bytes()
	if err != nil {
		return Nonce{}, false
	}
	var n Nonce
	_ = json.Unmarshal(b, &n)
	return n, true
}

func (s *redisStore) ConsumeNonce(v string) bool {
	n, ok := s.GetNonce(v)
	if !ok || n.Used || time.Now().After(n.Exp) {
		return false
	}
	n.Used = true
	s.PutNonce(n)
	return true
}

func (s *redisStore) PutSession(sess Session) {
	b, _ := json.Marshal(sess)
	s.rdb.Set(context.Background(), "siwe:sess:"+sess.Token, b, time.Until(sess.ExpiresAt))
}

func (s *redisStore) GetSession(tok string) (Session, bool) {
	b, err := s.rdb.Get(context.Background(), "siwe:sess:"+tok).Bytes()
	if err != nil {
		return Session{}, false
	}
	var out Session
	_ = json.Unmarshal(b, &out)
	return out, true
}

func (s *redisStore) DeleteSession(tok string) { s.rdb.Del(context.Background(), "siwe:sess:"+tok) }

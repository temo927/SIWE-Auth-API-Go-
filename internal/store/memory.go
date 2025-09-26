package store

import (
	"sync"
	"time"
)

type Nonce struct {
	Value string
	Exp   time.Time
	Used  bool
}

type Session struct {
	Token     string
	Address   string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

type Store interface {
	PutNonce(n Nonce)
	GetNonce(v string) (Nonce, bool)
	ConsumeNonce(v string) bool
	PutSession(s Session)
	GetSession(token string) (Session, bool)
	DeleteSession(token string)
}

type memory struct {
	mu      sync.RWMutex
	nonces  map[string]Nonce
	session map[string]Session
}

func NewMemoryStore() Store {
	return &memory{
		nonces:  make(map[string]Nonce),
		session: make(map[string]Session),
	}
}

func (m *memory) PutNonce(n Nonce) {
	m.mu.Lock()
	m.nonces[n.Value] = n
	m.mu.Unlock()
}

func (m *memory) GetNonce(v string) (Nonce, bool) {
	m.mu.RLock()
	n, ok := m.nonces[v]
	m.mu.RUnlock()
	return n, ok
}

func (m *memory) ConsumeNonce(v string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	n, ok := m.nonces[v]
	if !ok || n.Used || time.Now().After(n.Exp) {
		return false
	}
	n.Used = true
	m.nonces[v] = n
	return true
}

func (m *memory) PutSession(s Session) {
	m.mu.Lock()
	m.session[s.Token] = s
	m.mu.Unlock()
}

func (m *memory) GetSession(tok string) (Session, bool) {
	m.mu.RLock()
	s, ok := m.session[tok]
	m.mu.RUnlock()
	return s, ok
}

func (m *memory) DeleteSession(tok string) {
	m.mu.Lock()
	delete(m.session, tok)
	m.mu.Unlock()
}

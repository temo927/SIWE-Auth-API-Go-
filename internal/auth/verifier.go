package auth

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	siwe "github.com/spruceid/siwe-go"
	"github.com/temo927/SIWE-Auth-API-Go-/internal/config"
	"github.com/temo927/SIWE-Auth-API-Go-/internal/session"
	"github.com/temo927/SIWE-Auth-API-Go-/internal/store"
)

type Service struct {
	cfg *config.Config
	st  store.Store
	jwt *session.JWT
}

func NewService(cfg *config.Config, st store.Store, jwt *session.JWT) *Service {
	return &Service{cfg: cfg, st: st, jwt: jwt}
}

type nonceResp struct {
	Nonce string `json:"nonce"`
}

type prepareReq struct {
	Address   string `json:"address"`
	Nonce     string `json:"nonce"`
	ChainID   int    `json:"chainId"`
	Statement string `json:"statement"`
}

type prepareResp struct {
	Message string `json:"message"`
}

type verifyReq struct {
	Message   string `json:"message"`
	Signature string `json:"signature"`
}

type verifyResp struct {
	AccessToken string    `json:"accessToken"`
	Address     string    `json:"address"`
	ExpiresAt   time.Time `json:"expiresAt"`
}

func (s *Service) HandleNonce(w http.ResponseWriter, r *http.Request) (any, int, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return nil, http.StatusInternalServerError, err
	}
	nonce := hex.EncodeToString(buf)
	s.st.PutNonce(store.Nonce{Value: nonce, Exp: time.Now().Add(10 * time.Minute)})
	return nonceResp{Nonce: nonce}, http.StatusOK, nil
}

func (s *Service) HandlePrepare(w http.ResponseWriter, r *http.Request) (any, int, error) {
	var p prepareReq
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		return nil, http.StatusBadRequest, err
	}
	if p.Address == "" || p.Nonce == "" || p.ChainID == 0 {
		return nil, http.StatusBadRequest, errors.New("address, nonce, chainId required")
	}
	now := time.Now().UTC().Format(time.RFC3339)
	msg := fmt.Sprintf(
		"%s wants you to sign in with your Ethereum account:\n%s\n\n%s\n\nURI: %s\nVersion: 1\nChain ID: %d\nNonce: %s\nIssued At: %s",
		s.cfg.SIWEDomain,
		p.Address,
		p.Statement,
		s.cfg.SIWEURI,
		p.ChainID,
		p.Nonce,
		now,
	)
	return prepareResp{Message: msg}, http.StatusOK, nil
}

func (s *Service) HandleVerify(w http.ResponseWriter, r *http.Request) (any, int, error) {
	var req verifyReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, http.StatusBadRequest, err
	}
	if req.Message == "" || req.Signature == "" {
		return nil, http.StatusBadRequest, errors.New("message and signature required")
	}

	message, err := siwe.ParseMessage(req.Message)
	if err != nil {
		return nil, http.StatusBadRequest, err
	}

	addrStr := message.GetAddress().Hex()
	chainID := message.GetChainID()
	if _, ok := s.cfg.ChainIDs[uint64(chainID)]; !ok {
		return nil, http.StatusUnauthorized, errors.New("chainId not allowed")
	}

	domain := s.cfg.SIWEDomain
	nonce := message.GetNonce()
	now := time.Now().UTC()

	if _, err := message.Verify(req.Signature, &domain, &nonce, &now); err != nil {
		return nil, http.StatusUnauthorized, err
	}

	if ok := s.st.ConsumeNonce(nonce); !ok {
		return nil, http.StatusUnauthorized, errors.New("bad nonce")
	}

	tok, exp, err := s.jwt.Mint(addrStr)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	s.st.PutSession(store.Session{Token: tok, Address: addrStr, IssuedAt: time.Now().UTC(), ExpiresAt: exp})
	return verifyResp{AccessToken: tok, Address: addrStr, ExpiresAt: exp}, http.StatusOK, nil
}

func (s *Service) HandleMe(w http.ResponseWriter, r *http.Request) (any, int, error) {
	addr := session.AddrFromCtx(r.Context())
	if addr == "" {
		return nil, http.StatusUnauthorized, errors.New("no addr")
	}
	return map[string]any{"address": addr}, http.StatusOK, nil
}

func (s *Service) HandleLogout(w http.ResponseWriter, r *http.Request) (any, int, error) {
	return map[string]any{"ok": true}, http.StatusOK, nil
}

func equalAddr(a, b string) bool {
	return strings.EqualFold(common.HexToAddress(a).Hex(), common.HexToAddress(b).Hex())
}

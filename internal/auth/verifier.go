package auth
}
now := time.Now().UTC().Format(time.RFC3339)
msg := fmt.Sprintf(
"%s wants you to sign in with your Ethereum account:
%s


%s


URI: %s
Version: 1
Chain ID: %d
Nonce: %s
Issued At: %s",
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
return nil, http.StatusBadRequest, util.ErrBadRequest
}
if req.Message == "" || req.Signature == "" {
return nil, http.StatusBadRequest, util.ErrMissingFields
}
message, err := siwe.ParseMessage(req.Message)
if err != nil {
return nil, http.StatusBadRequest, err
}
addrStr := message.GetAddress().Hex()
chainID := message.GetChainID()
if _, ok := s.cfg.ChainIDs[uint64(chainID)]; !ok {
return nil, http.StatusUnauthorized, util.ErrChainNotAllowed
}
domain := s.cfg.SIWEDomain
nonce := message.GetNonce()
now := time.Now().UTC()
if _, err := message.Verify(req.Signature, &domain, &nonce, &now); err != nil {
return nil, http.StatusUnauthorized, util.ErrInvalidSignature
}
if ok := s.st.ConsumeNonce(nonce); !ok {
return nil, http.StatusUnauthorized, util.ErrBadNonce
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
return nil, http.StatusUnauthorized, util.ErrNoAddress
}
return map[string]any{"address": addr}, http.StatusOK, nil
}


func (s *Service) HandleLogout(w http.ResponseWriter, r *http.Request) (any, int, error) {
return map[string]any{"ok": true}, http.StatusOK, nil
}


func equalAddr(a, b string) bool { return strings.EqualFold(common.HexToAddress(a).Hex(), common.HexToAddress(b).Hex()) }
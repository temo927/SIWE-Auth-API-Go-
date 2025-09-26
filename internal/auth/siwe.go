package auth

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	siwe "github.com/spruceid/siwe-go"
)

type SIWEMessage struct {
	Raw string
	Msg *siwe.Message
}

func parseSIWE(raw string) (*SIWEMessage, error) {
	message, err := siwe.ParseMessage(raw)
	if err != nil {
		return nil, err
	}
	return &SIWEMessage{
		Raw: raw,
		Msg: message,
	}, nil
}
func (m *SIWEMessage) ValidateBasics(expectedDomain, expectedURI string, allowed map[uint64]struct{}, now time.Time) error {
	if expectedDomain != "" && !strings.EqualFold(m.Msg.GetDomain(), expectedDomain) {
		return fmt.Errorf("domain mismatch: %s", m.Msg.GetDomain())
	}
	if expectedURI != "" {
		u1, _ := url.Parse(expectedURI)
		u2 := m.Msg.GetURI()
		if u1.Scheme != u2.Scheme || u1.Host != u2.Host {
			return errors.New("uri mismatch")
		}
	}
	if _, ok := allowed[uint64(m.Msg.GetChainID())]; !ok {
		return fmt.Errorf("chainId %d not allowed", m.Msg.GetChainID())
	}
	valid, err := m.Msg.ValidAt(now.UTC())
	if err != nil {
		return err
	}
	if !valid {
		return errors.New("message not valid at the given time")
	}
	return nil
}

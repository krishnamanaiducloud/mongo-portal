package identity

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// Sealer encrypts and authenticates small values for cookies with
// AES-256-GCM. The key is derived from the portal session key and a purpose
// label, so values sealed for one purpose cannot be replayed as another.
// Every replica that shares the session key can open the values.
type Sealer struct {
	aead    cipher.AEAD
	purpose []byte
}

// ErrInvalidSeal means a sealed value is malformed, forged or expired.
var ErrInvalidSeal = errors.New("invalid or expired sealed value")

const sealPrefix = "v1."

// maxSealed bounds what Open accepts (browsers cap cookies at ~4 KiB).
const maxSealed = 4096

// NewSealer derives a purpose-specific key from key (at least 32 bytes).
func NewSealer(key []byte, purpose string) (*Sealer, error) {
	if len(key) < 32 {
		return nil, errors.New("sealer key must be at least 32 bytes")
	}
	m := hmac.New(sha256.New, key)
	m.Write([]byte("mongo-portal/seal/" + purpose))
	block, err := aes.NewCipher(m.Sum(nil))
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Sealer{aead: aead, purpose: []byte(purpose)}, nil
}

type sealed struct {
	Exp int64           `json:"e"`
	V   json.RawMessage `json:"v"`
}

// Seal encrypts v (JSON encoded) until exp.
func (s *Sealer) Seal(v any, exp time.Time) (string, error) {
	inner, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	plain, err := json.Marshal(sealed{Exp: exp.Unix(), V: inner})
	if err != nil {
		return "", err
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	out := s.aead.Seal(nonce, nonce, plain, s.purpose)
	return sealPrefix + base64.RawURLEncoding.EncodeToString(out), nil
}

// Open decrypts tok into v if it is authentic and not expired at now.
func (s *Sealer) Open(tok string, v any, now time.Time) error {
	if len(tok) > maxSealed || !strings.HasPrefix(tok, sealPrefix) {
		return ErrInvalidSeal
	}
	raw, err := base64.RawURLEncoding.DecodeString(tok[len(sealPrefix):])
	if err != nil || len(raw) < s.aead.NonceSize()+s.aead.Overhead() {
		return ErrInvalidSeal
	}
	ns := s.aead.NonceSize()
	plain, err := s.aead.Open(nil, raw[:ns], raw[ns:], s.purpose)
	if err != nil {
		return ErrInvalidSeal
	}
	var sv sealed
	if err := json.Unmarshal(plain, &sv); err != nil || now.Unix() >= sv.Exp {
		return ErrInvalidSeal
	}
	if err := json.Unmarshal(sv.V, v); err != nil {
		return ErrInvalidSeal
	}
	return nil
}

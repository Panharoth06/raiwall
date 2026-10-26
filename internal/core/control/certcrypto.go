package control

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
)

// CertSecretSetting stores the symmetric key used to encrypt TLS private keys at rest.
const CertSecretSetting = "cert_encryption_secret"

// EnsureCertificateSecret returns the AES key used for certificate private-key
// encryption, creating the persisted secret on first use.
func EnsureCertificateSecret(ctx context.Context, store ControlStore) ([]byte, error) {
	value, err := store.GetSetting(ctx, CertSecretSetting)
	if err != nil || value == "" {
		buf := make([]byte, 32)
		if _, randErr := rand.Read(buf); randErr != nil {
			return nil, fmt.Errorf("generate certificate secret: %w", randErr)
		}
		value = base64.RawURLEncoding.EncodeToString(buf)
		if putErr := store.PutSetting(ctx, CertSecretSetting, value); putErr != nil {
			return nil, fmt.Errorf("persist certificate secret: %w", putErr)
		}
	}
	sum := sha256.Sum256([]byte(value))
	return sum[:], nil
}

// EncryptPrivateKey seals a PEM private key with AES-256-GCM.
func EncryptPrivateKey(key []byte, plaintext string) (string, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}
	sealed := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// DecryptPrivateKey opens a private key sealed with EncryptPrivateKey.
func DecryptPrivateKey(key []byte, encoded string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("decode encrypted key: %w", err)
	}
	gcm, err := newGCM(key)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", fmt.Errorf("encrypted key is truncated")
	}
	nonce, ciphertext := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decrypt private key: %w", err)
	}
	return string(plaintext), nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	return cipher.NewGCM(block)
}

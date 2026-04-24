package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const KeySize = 32

type Key struct {
	data [KeySize]byte
}

func (k *Key) String() string {
	return hex.EncodeToString(k.data[:])
}

var (
	ErrInvalidKeyLength   = errors.New("crypto: invalid key length for parsing")
	ErrCiphertextTooShort = errors.New("crypto: ciphertext is too short")
	ErrDecryptFailed      = errors.New("crypto: decrypt failed (possible corrupted data, wrong key, or mismatched ID)")
	ErrEntropySource      = errors.New("crypto: failed to read random bytes")
	ErrKeyDerivation      = errors.New("crypto: key derivation failed")
	ErrInvalidHexFormat   = errors.New("crypto: key is not a valid hex string")
)

func GenerateKey() (*Key, error) {
	var key Key
	if _, err := rand.Read(key.data[:]); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEntropySource, err)
	}
	return &key, nil
}

func ParseHexString(hexStr string) (*Key, error) {
	decoded, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidHexFormat, err)
	}
	return parseKey(decoded)
}

func parseKey(b []byte) (*Key, error) {
	if len(b) != KeySize {
		return nil, ErrInvalidKeyLength
	}

	var key Key
	copy(key.data[:], b)
	return &key, nil
}

type Secret struct {
	dataKey []byte
}

func New(key *Key, info []byte) (*Secret, error) {
	s := &Secret{}
	if err := s.deriveDataKey(key.data[:], info); err != nil {
		return nil, err
	}

	return s, nil
}

func (s *Secret) Encrypt(plaintext, recordID []byte) ([]byte, error) {
	recordKey, err := s.deriveRecordKey(recordID)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(recordKey)
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEntropySource, err)
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, recordID)
	return ciphertext, nil
}

func (s *Secret) Decrypt(ciphertext, recordID []byte) ([]byte, error) {
	recordKey, err := s.deriveRecordKey(recordID)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(recordKey)
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, ErrCiphertextTooShort
	}

	nonce, actualCiphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, actualCiphertext, recordID)
	if err != nil {
		return nil, ErrDecryptFailed
	}

	return plaintext, nil
}

func (s *Secret) deriveDataKey(secret, info []byte) error {
	h := hkdf.New(sha256.New, secret, nil, info)
	key := make([]byte, KeySize)
	if _, err := io.ReadFull(h, key); err != nil {
		return fmt.Errorf("%w: %v", ErrKeyDerivation, err)
	}
	s.dataKey = key
	return nil
}

func (s *Secret) deriveRecordKey(recordID []byte) ([]byte, error) {
	info := append([]byte("record-key:"), recordID...)
	h := hkdf.Expand(sha256.New, s.dataKey, info)

	key := make([]byte, KeySize)
	if _, err := io.ReadFull(h, key); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeyDerivation, err)
	}
	return key, nil
}

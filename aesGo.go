package aes256andrew

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"sync"
)

var (
	errCiphertextTooShort = errors.New("ciphertext too short")
)

// Buffer pool for performance optimization
var bufferPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 64)
		return &b
	},
}

// Encrypt шифрует заданный открытый текст с использованием AES-256.
// Возвращает зашифрованный шифротекст и ключ, использованный для шифрования.
func Encrypt(plaintext string) (string, []byte, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return "", nil, fmt.Errorf("failed to generate key: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create cipher block: %w", err)
	}

	// Ensure the buffer is large enough to hold the ciphertext
	ciphertextPtr := bufferPool.Get().(*[]byte)
	ciphertext := *ciphertextPtr
	if cap(ciphertext) < aes.BlockSize+len(plaintext) {
		ciphertext = make([]byte, aes.BlockSize+len(plaintext))
	} else {
		ciphertext = ciphertext[:aes.BlockSize+len(plaintext)]
	}
	defer func() {
		bufferPool.Put(&ciphertext)
	}()

	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", nil, fmt.Errorf("failed to generate IV: %w", err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(plaintext))

	return base64.URLEncoding.EncodeToString(ciphertext), key, nil
}

// Decrypt дешифрует заданный шифротекст с использованием AES-256.
// Возвращает расшифрованный открытый текст.
func Decrypt(ciphertext string, key []byte) (string, error) {
	data, err := base64.URLEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64 ciphertext: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher block: %w", err)
	}

	if len(data) < aes.BlockSize {
		return "", errCiphertextTooShort
	}

	iv := data[:aes.BlockSize]
	data = data[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(data, data)

	return string(data), nil
}

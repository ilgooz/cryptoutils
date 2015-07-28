package cryptoutils

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

var Key = "big awesome secret stands here"

func ComputeHmac256(message string) string {
	key := []byte(Key)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(message))
	return fmt.Sprintf("%x", h.Sum(nil))
}

func Hash(s string, level int) (string, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(s), level)
	if err != nil {
		return "", nil
	}
	return string(hashed), nil
}

func RandToken(size int) string {
	b := make([]byte, size)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

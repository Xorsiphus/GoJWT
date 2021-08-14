package Tokens

import (
	"encoding/base64"
	"golang.org/x/crypto/bcrypt"
	"time"
)

// GenerateSimpleToken Генерация refresh токена для отправки (base64 alg)
func GenerateSimpleToken(userId string) (string, time.Time) {
	expirationTime := time.Now().Add(5 * time.Minute)

	// Генерация основы refresh токена
	refreshBase := string(expirationTime.AppendFormat(nil, time.RFC3339)) + "~" + userId

	refreshTokenString := base64.StdEncoding.EncodeToString(
		[]byte(refreshBase))

	return refreshTokenString, expirationTime
}

// GenerateSimpleTokenHash Генерация refresh токена для бд (bcrypt alg)
func GenerateSimpleTokenHash(userId string) ([]byte, error){
	expirationTime := time.Now().Add(5 * time.Minute)

	// Генерация основы refresh токена
	refreshBase := string(expirationTime.AppendFormat(nil, time.RFC3339)) + "~" + userId

	return bcrypt.GenerateFromPassword([]byte(refreshBase), 12)
}

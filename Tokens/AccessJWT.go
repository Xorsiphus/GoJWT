package Tokens

import (
	"GoJWT/Configuration"
	"github.com/golang-jwt/jwt"
	"time"
)

// GenerateJWT Генерация access токена (SHA512 alg)
func GenerateJWT(userId string) (string, error, time.Time) {
	expirationTime := time.Now().Add(time.Minute * 5)

	// Генерация Claims для токена
	claims := &Configuration.Claims{
		UserId: userId,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	accessTokenStr, err := accessToken.SignedString(Configuration.JwtKey)
	return accessTokenStr, err, expirationTime
}

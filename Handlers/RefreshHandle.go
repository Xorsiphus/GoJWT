package Handlers

import (
	"GoJWT/Configuration"
	"GoJWT/MongoDb"
	"GoJWT/Tokens"
	"encoding/base64"
	"github.com/golang-jwt/jwt"
	"net/http"
	"strings"
	"time"
)

func Refresh(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// Получение access токена из cookie
	accessTokenCookie, err := r.Cookie(Configuration.AccessTokenCookieName)
	if err != nil {
		if err == http.ErrNoCookie {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	accessTokenClaims := &Configuration.Claims{}

	// Проверка аутентичности access токена
	tkn, _ := jwt.ParseWithClaims(accessTokenCookie.Value, accessTokenClaims,
		func(t *jwt.Token) (interface{}, error) {
			return Configuration.JwtKey, nil
		})

	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if tkn != nil && !tkn.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Получение refresh токена из cookie
	refreshTokenCookie, err := r.Cookie(Configuration.RefreshTokenCookieName)
	if err != nil {
		if err == http.ErrNoCookie {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Расшифровка токена из base64
	refreshToken, err := base64.StdEncoding.DecodeString(refreshTokenCookie.Value)

	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	params := strings.Split(string(refreshToken), "~")

	// Проверка аутентичности refresh токена
	refreshTokenUserId := params[1]

	if !MongoDb.CheckHash(refreshTokenUserId, refreshToken) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Incorrect refresh token!"))
		return
	}

	// Проверка принадлежности токенов одному пользователю
	if refreshTokenUserId != accessTokenClaims.UserId {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Tokens belong to different users!"))
		return
	}

	// Проверка актуальности токена
	expirationTime, err := time.Parse(time.RFC3339, params[0])

	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		return
	}

	if expirationTime.Before(time.Now()) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Refresh token expired!"))
		return
	}

	// Обновление access токена
	userId := params[1]
	accessTokenString, err, expirationTime := Tokens.GenerateJWT(userId)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:    Configuration.AccessTokenCookieName,
		Value:   accessTokenString,
		Expires: expirationTime,
	})

	// Обновление refresh токена
	refreshTokenString, expirationTime := Tokens.GenerateSimpleToken(userId)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:    Configuration.RefreshTokenCookieName,
		Value:   refreshTokenString,
		Expires: expirationTime,
	})

	refreshTokenHash, err := Tokens.GenerateSimpleTokenHash(userId)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return
	}

	MongoDb.AddHash(userId, string(refreshTokenHash))
}
package Handlers

import (
	"GoJWT/Configuration"
	"GoJWT/MongoDb"
	"GoJWT/Tokens"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
)

func Refresh(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Write([]byte("Only 'POST' and 'GET' methods is available!"))
		return
	}

	if r.Method == http.MethodGet {
		body, err := ioutil.ReadFile(Configuration.ViewsTemplate + "refresh.html")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(err.Error()))
			return
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, string(body))

		return
	}

	// Получение access токена из cookie
	accessTokenCookie, err := r.Cookie(Configuration.AccessTokenCookieName)
	if err != nil {
		if err == http.ErrNoCookie {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(err.Error()))
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
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
			w.Write([]byte(err.Error()))
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		return
	}

	if tkn != nil && !tkn.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(Configuration.UnauthorizedString))
		return
	}

	// Получение refresh токена из cookie
	refreshTokenCookie, err := r.Cookie(Configuration.RefreshTokenCookieName)
	if err != nil {
		if err == http.ErrNoCookie {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(err.Error()))
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		return
	}

	// Расшифровка токена из base64
	refreshToken, err := base64.StdEncoding.DecodeString(refreshTokenCookie.Value)

	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		return
	}

	params := strings.Split(string(refreshToken), "~")

	// Проверка аутентичности refresh токена
	refreshTokenUserId := params[1]

	err = MongoDb.CheckHash(refreshTokenUserId, refreshToken)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(err.Error()))
		return
	}

	// Проверка принадлежности токенов одному пользователю
	if refreshTokenUserId != accessTokenClaims.UserId {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Tokens belong to different users!"))
		return
	}

	// Проверка актуальности refresh токена
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

	err = MongoDb.AddHash(userId, string(refreshTokenHash))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Successfully updated!"))
}

package Handlers

import (
	"GoJWT/Configuration"
	"github.com/dgrijalva/jwt-go"
	"net/http"
)

func Home(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	cookie, err := r.Cookie(Configuration.AccessTokenCookieName)
	if err != nil {
		if err == http.ErrNoCookie {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	accessTokenStr := cookie.Value

	claims := &Configuration.Claims{}

	tkn, err := jwt.ParseWithClaims(
		accessTokenStr,
		claims,
		func(_ *jwt.Token) (interface{}, error) {
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

	if !tkn.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(claims.UserId))

	return
}

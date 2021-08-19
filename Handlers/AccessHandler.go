package Handlers

import (
	"GoJWT/Configuration"
	"net/http"

	"github.com/golang-jwt/jwt"
)

func Home(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Write([]byte("Method not allowed!"))
		return
	}

	cookie, err := r.Cookie(Configuration.AccessTokenCookieName)
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
			w.Write([]byte(err.Error()))
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		return
	}

	if !tkn.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(Configuration.UnauthorizedString))
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Authorized Username: " + claims.UserId))
}

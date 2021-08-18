package Handlers

import (
	"GoJWT/Configuration"
	"net/http"
	"time"
)

func Clear(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w,
		&http.Cookie{
			Name:    Configuration.AccessTokenCookieName,
			Expires: time.Now().Add(-time.Minute),
		})

	http.SetCookie(w,
		&http.Cookie{
			Name:    Configuration.RefreshTokenCookieName,
			Expires: time.Now().Add(-time.Minute),
		})

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Cookies has been cleared!"))
}

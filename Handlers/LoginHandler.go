package Handlers

import (
	"GoJWT/Configuration"
	"GoJWT/MongoDb"
	"GoJWT/Tokens"
	"fmt"
	"net/http"
)

// Login Обработка Get запроса на получение токенов
func Login(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// Получение UserId из параметров запроса
	query, present := r.URL.Query()["userId"]

	fmt.Printf("%v", query)

	if !present || len(query) != 1 {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(Configuration.InvalidQueryString))
		fmt.Println(Configuration.InvalidQueryString)
		return
	}

	userId := query[0]

	// Генерация access токена (SHA512 alg)
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

	// Генерация refresh токена для отправки (base64 alg)
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

	// Генерация refresh токена для бд (bcrypt alg)
	refreshTokenHash, err := Tokens.GenerateSimpleTokenHash(userId)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return
	}

	// Сохранение хеша refresh токена
	err = MongoDb.AddHash(userId, string(refreshTokenHash))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(userId + " has been authorized"))
}

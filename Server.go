package main

import (
	"GoJWT/Handlers"
	"GoJWT/MongoDb"
	"log"
	"net/http"
)

func main() {
	MongoDb.Connect()
	defer MongoDb.Disconnect()
	http.HandleFunc("/login", Handlers.Login)
	http.HandleFunc("/refresh", Handlers.Refresh)
	http.HandleFunc("/home", Handlers.Home)
	http.HandleFunc("/clear", Handlers.Clear)

	log.Fatal(http.ListenAndServe(":8080", nil))
}
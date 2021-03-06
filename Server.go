package main

import (
	"GoJWT/Configuration"
	"GoJWT/Handlers"
	"GoJWT/MongoDb"
	"log"
	"net/http"
)

func main() {
	err := MongoDb.Connect()
	if err != nil {
		log.Fatal(err.Error())
		return
	}
	defer MongoDb.Disconnect()
	http.HandleFunc("/login", Handlers.Login)
	http.HandleFunc("/refresh", Handlers.Refresh)
	http.HandleFunc("/home", Handlers.Home)
	http.HandleFunc("/clear", Handlers.Clear)

	log.Printf("Listening %v", Configuration.Addr)

	defer log.Fatal(http.ListenAndServe(Configuration.Addr, nil))
}
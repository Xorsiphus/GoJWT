package Configuration

import (
	"github.com/dgrijalva/jwt-go"
	"os"
)

// var JwtKey = []byte("key")
var JwtKey = []byte(os.Getenv("JWT_SECRET"))
var UserColumn = "user_id"
var HashColumn = "hash"
var AccessTokenCookieName = "accessToken"
var RefreshTokenCookieName = "refreshToken"
var Addr = ":5010"

type Claims struct {
	UserId string `json:"userid"`
	jwt.StandardClaims
}

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

type Claims struct {
	UserId string `json:"userid"`
	jwt.StandardClaims
}

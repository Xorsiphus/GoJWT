package Configuration

import (
	"os"

	"github.com/golang-jwt/jwt"
)

// var JwtKey = []byte("key")
var JwtKey = []byte(os.Getenv("JWT_SECRET"))
var UserColumn = "user_id"
var HashColumn = "hash"
var AccessTokenCookieName = "accessToken"
var RefreshTokenCookieName = "refreshToken"
var ViewsTemplate = "Views/"
var Addr = ":5010"
var DbErrorString = "database error"
var UnauthorizedString = "Unauthorized!"
var InvalidQueryString = "Invalid query!"

type Claims struct {
	UserId string `json:"userid"`
	jwt.StandardClaims
}

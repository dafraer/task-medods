package token

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const (
	refreshTokenLiveSpan = time.Hour * 24
	accessTokenLiveSpan  = time.Minute * 15
)

type JWTManager struct {
	signingKey string
}

type TokensPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func New(signingKey string) *JWTManager {
	return &JWTManager{
		signingKey: signingKey,
	}
}

// Include IP Address in CustomClaims to use it when refreshing token
type CustomClaims struct {
	jwt.RegisteredClaims
	IPAddress string `json:"ip_address"`
}

// NewAccessToken generates a JWT token using SHA512 algorithm
func (maker *JWTManager) NewAccessToken(id, userId, ipAddress string) (string, *CustomClaims, error) {
	claims := CustomClaims{
		IPAddress: ipAddress,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(accessTokenLiveSpan)),
			Subject:   userId,
			ID:        id,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	accessToken, err := token.SignedString([]byte(maker.signingKey))
	if err != nil {
		return "", nil, err
	}
	return accessToken, &claims, nil
}

// Verify verifies JWT token ans returns token's payload
func (maker *JWTManager) Verify(tokenString string) (*CustomClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("invalid signing method")
		}
		return []byte(maker.signingKey), nil
	})
	//Ignore TokenExpired error because we are refreshing access token
	if err != nil && !errors.Is(err, jwt.ErrTokenExpired) {
		return nil, err
	}

	claims, ok := token.Claims.(*CustomClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}
	return claims, nil
}

// NewRefreshToken returns a uuid as a token
func NewRefreshToken() (string, time.Time) {
	return uuid.New().String(), time.Now().Add(refreshTokenLiveSpan)
}

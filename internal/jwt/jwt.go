package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"log"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type JWT struct {
	PrivateKey             *rsa.PrivateKey
	PublicKey              *rsa.PublicKey
	AccessTokenExpiration  time.Duration
	RefreshTokenExpiration time.Duration
}

type Config struct {
	Key                    string `yaml:"private_key" env-prefix:"PRIVATEKEY" env-default:""`
	AccessTokenExpiration  int    `yaml:"access_token_expiration" env-prefix:"ACCESSTOKENEXPIRATION" env-default:"3600"`
	RefreshTokenExpiration int    `yaml:"refresh_token_expiration" env-prefix:"PRIVATEKEY" env-default:"36000"`
}

// Создает jwt объект с ключами и сроком действия токенов
func New(cfg *Config) (JWT, error) {
	jwt := JWT{}
	var err error
	privateKeyString := cfg.Key
	jwt.AccessTokenExpiration = time.Second * time.Duration(cfg.AccessTokenExpiration)
	jwt.RefreshTokenExpiration = time.Second * time.Duration(cfg.RefreshTokenExpiration)
	if privateKeyString == "" {
		jwt.PrivateKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return JWT{}, err
		}
		jwt.PublicKey = &jwt.PrivateKey.PublicKey
		return jwt, nil
	}
	keyBytes := convertStringToBytesSlice(privateKeyString)
	jwt.PrivateKey, err = x509.ParsePKCS1PrivateKey(keyBytes)
	jwt.PublicKey = &jwt.PrivateKey.PublicKey
	if err != nil {
		slog.Error("JWT: New:", "error", err)
		return JWT{}, err
	}
	return jwt, nil
}

func (j *JWT) CreateAccessToken(id uuid.UUID, tokenID uuid.UUID) (string, error) {
	accessToken, err := jwt.NewWithClaims(jwt.SigningMethodRS512, jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(j.AccessTokenExpiration)),
		Subject:   id.String() + "/" + tokenID.String(),
	}).SignedString(j.PrivateKey)
	if err != nil {
		slog.Error("JWT: CreateAccessToken:", "error", err)
		return "", err
	}
	return accessToken, nil
}

func (j *JWT) CreateRefreshToken(tokenID uuid.UUID) (string, error) {
	return base64.StdEncoding.EncodeToString(tokenID[:]), nil
}

func (j *JWT) GetIDFromRefreshToken(token string) (uuid.UUID, error) {
	bytesID, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		slog.Error("JWT: GetIDFromRefreshToken:", "error", err)
		return uuid.Nil, err
	}
	log.Println(bytesID)
	id, err := uuid.FromBytes(bytesID)
	if err != nil {
		slog.Error("JWT: GetIDFromRefreshToken: can't parse bytes", "bytesID", bytesID, "error", err)
		return uuid.Nil, err
	}
	return id, nil
}

func (j *JWT) GetSubjectFromToken(token string) (string, error) {
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return j.PublicKey, nil
	})
	if err != nil {
		slog.Error("JWT: GetSubjectFromToken: can't parse with claims", "error", err)
		return "", err
	}
	id := claims["sub"].(string)
	return id, nil
}

func convertStringToBytesSlice(line string) []byte {
	line = strings.Trim(line, "[]")
	parts := strings.Split(line, " ")
	var bytes []byte
	for _, part := range parts {
		num, err := strconv.Atoi(part)
		if err != nil {
			panic(err)
		}
		bytes = append(bytes, byte(num))
	}
	return bytes
}

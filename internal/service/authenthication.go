package service

import (
	"errors"
	"log/slog"
	"medods_test/pkg/cerr"
	"medods_test/pkg/models"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type DB interface {
	UpdateRefreshToken(id uuid.UUID, token []byte) error
	GetRefreshToken(id uuid.UUID) ([]byte, error)
}

type JWT interface {
	CreateAccessToken(id uuid.UUID, tokenID uuid.UUID, userAgent, ip string) (string, error)
	CreateRefreshToken(tokenID uuid.UUID) (string, error)
	GetSubjectFromToken(token string) (string, error)
	GetIDFromRefreshToken(token string) (uuid.UUID, error)
}

func (s Service) CreateTokens(id uuid.UUID, userAgent, ip string) (*models.Tokens, error) {
	tokensID := uuid.New()
	access, err := s.j.CreateAccessToken(id, tokensID, userAgent, ip)
	if err != nil {
		return nil, err
	}
	refresh, err := s.j.CreateRefreshToken(tokensID)
	if err != nil {
		return nil, err
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(refresh), bcrypt.DefaultCost)
	if err != nil {
		slog.Error("Service: can't generate hash from token:", "error", err)
		return nil, err
	}

	err = s.db.UpdateRefreshToken(id, hash)
	if err != nil {
		return nil, err
	}

	return &models.Tokens{AccessToken: access, RefreshToken: refresh}, nil
}

func (s Service) RefreshTokens(tokens models.Tokens, userAgent, ip string) (*models.Tokens, error) {
	data, err := s.getAccessData(tokens.AccessToken)
	if err != nil {
		return nil, err
	}

	id := data[0]
	accessID := data[1]
	tokenAgent := data[2]
	tokenIP := data[3]

	if tokenAgent != userAgent {
		s.KillTokens(tokens.AccessToken)
		return nil, cerr.UserAgentMismatch
	}

	if tokenIP != ip {
		s.sendMockAttentionMessage(ip)
	}

	userID, err := uuid.Parse(id)
	if err != nil {
		slog.Error("Service: RefreshToken: can't parse user id", "error", err)
		return nil, err
	}

	storedRefresh, err := s.db.GetRefreshToken(userID)
	if err != nil {
		return nil, err
	}

	err = bcrypt.CompareHashAndPassword(storedRefresh, []byte(tokens.RefreshToken))
	if err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			slog.Info("Got:", "token", tokens.RefreshToken, "stored", storedRefresh)
			return nil, cerr.RefreshDontMatch
		}
		slog.Error("Service: RefreshToken: can't compare hash and password", "error", err)
		return nil, err
	}

	refreshID, err := s.j.GetIDFromRefreshToken(tokens.RefreshToken)
	if err != nil {
		return nil, err
	}

	if refreshID.String() != accessID {
		return nil, cerr.IDDontMatch
	}

	return s.CreateTokens(userID, userAgent, ip)
}

func (s Service) GetID(accessToken string) (uuid.UUID, error) {
	data, err := s.getAccessData(accessToken)
	if err != nil {
		return uuid.Nil, err
	}

	id := data[0]
	accessID := data[1]

	userID, err := uuid.Parse(id)
	if err != nil {
		slog.Error("Service: GetID: can't parse user id", "error", err)
		return uuid.Nil, err
	}

	tokensID, err := uuid.Parse(accessID)
	if err != nil {
		slog.Error("Service: GetID: can't parse tokens id", "error", err)
		return uuid.Nil, err
	}

	pseudoToken, err := s.j.CreateRefreshToken(tokensID)
	if err != nil {
		return uuid.Nil, err
	}

	refreshTokenHash, err := s.db.GetRefreshToken(userID)
	if err != nil {
		return uuid.Nil, err
	}

	err = bcrypt.CompareHashAndPassword(refreshTokenHash, []byte(pseudoToken))
	if err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return uuid.Nil, cerr.AccessTokenKilled
		}
		slog.Error("Service: RefreshToken: can't compare hash and password", "error", err)
		return uuid.Nil, err
	}

	return userID, nil
}

func (s Service) KillTokens(accessToken string) error {
	id, err := s.GetID(accessToken)
	if err != nil {
		return err
	}

	tokensID := uuid.New()

	refresh, err := s.j.CreateRefreshToken(tokensID)
	if err != nil {
		return err
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(refresh), bcrypt.DefaultCost)
	if err != nil {
		slog.Error("Service: can't generate hash from token:", "error", err)
		return err
	}

	err = s.db.UpdateRefreshToken(id, hash)
	if err != nil {
		return err
	}

	return nil
}

func (s *Service) getAccessData(accessToken string) ([]string, error) {
	accessSubject, err := s.j.GetSubjectFromToken(accessToken)
	if err != nil {
		return nil, err
	}
	accessData := strings.Split(accessSubject, "*/")
	return accessData, nil
}

func (s *Service) sendMockAttentionMessage(ip string) error {
	slog.Info("User refreshed tokens from another ip:", "ip", ip)
	time.Sleep(time.Millisecond * 300)
	return nil
}

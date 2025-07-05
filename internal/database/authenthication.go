package database

import (
	"context"
	"log/slog"

	"github.com/google/uuid"
)

func (d *DB) UpdateRefreshToken(id uuid.UUID, token []byte) error {
	_, err := d.db.Exec(context.Background(), `insert into users(id, token) values($1, $2) on conflict(id) do update set token = $3`, id, token, token)
	if err != nil {
		slog.Error("DB: UpdateRefreshToken: can't insert/update user token", "error", err)
		return err
	}
	return nil
}

func (d *DB) GetRefreshToken(id uuid.UUID) ([]byte, error) {
	var tokenHash []byte
	err := d.db.QueryRow(context.Background(), `select token from users where id=$1`, id).Scan(&tokenHash)
	if err != nil {
		slog.Error("DB: GetRefreshToken: can't get refresh token", "error", err)
		return nil, err
	}
	return tokenHash, nil
}

package database

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"log/slog"

	"github.com/mbvlabs/mithlond-ce/config"

	_ "github.com/mattn/go-sqlite3"
)

var (
	ErrBeginTx    = errors.New("could not begin transaction")
	ErrRollbackTx = errors.New("could not rollback transaction")
	ErrCommitTx   = errors.New("could not commit transaction")
)

//go:embed migrations/*
var Migrations embed.FS

type SQLite struct {
	db *sql.DB
}

func NewSQLite(ctx context.Context) (SQLite, error) {
	db, err := sql.Open("sqlite3", config.DB.GetDatabaseURL())
	if err != nil {
		slog.ErrorContext(ctx, "could not open sqlite database", "error", err)
		return SQLite{}, err
	}

	if err := db.PingContext(ctx); err != nil {
		slog.ErrorContext(ctx, "could not ping database", "error", err)
		return SQLite{}, err
	}

	return SQLite{db}, nil
}

func (s *SQLite) Conn() *sql.DB {
	return s.db
}

func (s *SQLite) BeginTx(ctx context.Context) (*sql.Tx, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		slog.ErrorContext(ctx, "could not begin transaction", "reason", err)
		return nil, errors.Join(ErrBeginTx, err)
	}

	return tx, nil
}

func (s *SQLite) RollBackTx(ctx context.Context, tx *sql.Tx) error {
	if err := tx.Rollback(); err != nil {
		slog.ErrorContext(ctx, "could not rollback transaction", "reason", err)
		return errors.Join(ErrRollbackTx, err)
	}

	return nil
}

func (s *SQLite) CommitTx(ctx context.Context, tx *sql.Tx) error {
	if err := tx.Commit(); err != nil {
		slog.ErrorContext(ctx, "could not commit transaction", "reason", err)
		return errors.Join(ErrCommitTx, err)
	}

	return nil
}

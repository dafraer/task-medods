package store

import (
	"context"
	"database/sql"

	_ "github.com/lib/pq"
)

type Storer interface {
	GetSession(ctx context.Context, tokenId string) (*Session, error)
	Init(ctx context.Context) error
	RevokeSession(ctx context.Context, id string) error
	SaveSession(ctx context.Context, session *Session) error
}

type Store struct {
	db *sql.DB
}

type Session struct {
	Id           string
	RefreshToken string
	IPAddress    string
	IsRevoked    bool
	ExpiresAt    int64
}

func New(db *sql.DB) *Store {
	return &Store{
		db: db,
	}
}

func (s *Store) Init(ctx context.Context) error {
	return s.createSessionsTable(ctx)
}

func (s *Store) createSessionsTable(ctx context.Context) error {
	query := `CREATE TABLE IF NOT EXISTS sessions (
		id TEXT PRIMARY KEY,
		refresh_token TEXT,
		ip_address TEXT,
		is_revoked BOOL,
		expires_at INT
	);`

	_, err := s.db.ExecContext(ctx, query)
	return err
}

// SaveSession saves session using hashed refresh token
func (s *Store) SaveSession(ctx context.Context, session *Session) error {
	query := `INSERT INTO sessions (id, refresh_token, ip_address,  is_revoked, expires_at) VALUES ($1, $2, $3, $4, $5);`
	_, err := s.db.ExecContext(ctx, query, session.Id, session.RefreshToken, session.IPAddress, session.IsRevoked, session.ExpiresAt)
	return err
}

// RevokeSession sets is_revoked to true
func (s *Store) RevokeSession(ctx context.Context, id string) error {
	query := `UPDATE sessions SET is_revoked=TRUE WHERE id = $1;`
	_, err := s.db.ExecContext(ctx, query, id)
	return err
}

// GetSession returns session with a refresh token hash by tokenId
func (s *Store) GetSession(ctx context.Context, tokenId string) (*Session, error) {
	query := `SELECT id, refresh_token, ip_address,  is_revoked, expires_at FROM sessions WHERE id = $1`
	var session Session
	err := s.db.QueryRowContext(ctx, query, tokenId).Scan(
		&session.Id,
		&session.RefreshToken,
		&session.IPAddress,
		&session.IsRevoked,
		&session.ExpiresAt,
	)
	if err != nil {
		return nil, err
	}
	return &session, nil
}

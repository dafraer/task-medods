package store

import (
	"context"
	"database/sql"
	"testing"

	"github.com/stretchr/testify/assert"
)

var testSession = Session{
	Id:           "1",
	RefreshToken: "test_hash",
	IPAddress:    "172.0.0.1",
	IsRevoked:    false,
	ExpiresAt:    1764743068,
}

func TestInit(t *testing.T) {
	conn, err := createDBConnection()
	assert.NoError(t, err)
	db := New(conn)
	assert.NoError(t, err)
	assert.NoError(t, db.Init(context.Background()))
}

func TestSaveSession(t *testing.T) {
	//Create new db object
	conn, err := createDBConnection()
	assert.NoError(t, err)
	db := New(conn)
	assert.NoError(t, err)
	//Clear storage to prevent collisions
	assert.NoError(t, db.clearStorage())

	//Create sessions table in the database
	if err = db.Init(context.Background()); err != nil {
		t.Error(err)
	}

	if err = db.SaveSession(context.Background(), &testSession); err != nil {
		t.Error(err)
	}

}

func TestRevokeSession(t *testing.T) {
	//Create new db object
	conn, err := createDBConnection()
	assert.NoError(t, err)
	db := New(conn)

	//Clear storage to prevent collisions
	assert.NoError(t, db.clearStorage())

	//Create sessions table in the database
	assert.NoError(t, db.Init(context.Background()))

	assert.NoError(t, db.SaveSession(context.Background(), &testSession))

	assert.NoError(t, db.RevokeSession(context.Background(), testSession.Id))
}

func TestGetSession(t *testing.T) {
	//Create new db object
	conn, err := createDBConnection()
	assert.NoError(t, err)
	db := New(conn)

	//Clear storage to prevent collisions
	assert.NoError(t, db.clearStorage())

	//Create sessions table in the database
	assert.NoError(t, db.Init(context.Background()))
	assert.NoError(t, db.SaveSession(context.Background(), &testSession))

	//Get session from db by id
	session, err := db.GetSession(context.Background(), testSession.Id)
	assert.NoError(t, err)

	//Session must be the same session we saved earlier
	assert.Equal(t, *session, testSession)
}

// clearStorage drops sessions tables to avoid collisions when testing
func (s *Store) clearStorage() error {
	if _, err := s.db.Exec("DROP TABLE IF EXISTS sessions"); err != nil {
		return err
	}
	return nil
}

// createDBConnection is a helper function to create *sqlDB
func createDBConnection() (*sql.DB, error) {
	//Create storagee
	connStr := "user=postgres dbname=postgres password=mysecretpassword sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		return nil, err
	}
	return db, err
}

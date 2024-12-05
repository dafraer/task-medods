package store

import "context"

type MockStore struct {
	session *Session
}

func NewMockStore() *MockStore {
	return &MockStore{&Session{}}
}

func (s *MockStore) Init(ctx context.Context) error {
	return nil
}

func (s *MockStore) GetSession(ctx context.Context, tokenId string) (*Session, error) {
	return s.session, nil
}

func (s *MockStore) RevokeSession(ctx context.Context, id string) error {
	s.session.IsRevoked = true
	return nil
}

func (s *MockStore) SaveSession(ctx context.Context, session *Session) error {
	s.session = session
	return nil
}

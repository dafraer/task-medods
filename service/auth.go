package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/smtp"
	"sync"
	"task/store"
	"task/token"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type AuthService struct {
	tokenMaker *token.JWTManager
	storage    store.Storer
	wg         sync.WaitGroup
}

func New(signingKey string, storage store.Storer) (*AuthService, error) {
	manager := token.New(signingKey)
	return &AuthService{manager, storage, sync.WaitGroup{}}, nil
}

func (s *AuthService) Run(ctx context.Context, address string) error {
	srv := &http.Server{
		Addr:        address,
		BaseContext: func(net.Listener) context.Context { return ctx },
	}
	//Two REST routes: one for generating a pair of access and refresh tokens
	http.HandleFunc("/generate", s.handleGenerate)
	http.HandleFunc("/refresh", s.handleRefresh)
	ch := make(chan error)
	go func() {
		defer close(ch)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			ch <- err
			return
		}
		ch <- nil
	}()
	select {
	case <-ctx.Done():
		if err := srv.Shutdown(context.Background()); err != nil {
			return err
		}
		err := <-ch
		if err != nil {
			return err
		}
	case err := <-ch:
		return err
	}
	s.wg.Wait()
	return nil
}

func (s *AuthService) handleGenerate(w http.ResponseWriter, r *http.Request) {
	//Get user Id from request
	userId := r.FormValue("id")

	//Chechk that id parameter isnt empty
	if userId == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	//Create access and refresh tokens
	accessToken, refreshToken, err := s.createPairTokens(r.Context(), userId, r.RemoteAddr)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Println("Error creating tokens:", err)
		return
	}
	//Create a json object from tokens
	response, err := json.Marshal(token.TokensPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Println("Error marshaling json:", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(response); err != nil {
		log.Println("Error writing a response")
	}
}

func (s *AuthService) handleRefresh(w http.ResponseWriter, r *http.Request) {
	//Decode request into a map
	var req token.TokensPair
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Println("Error decoding json:", err)
		return
	}

	//Check that parameters are not empty
	if req.AccessToken == "" || req.RefreshToken == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	//Verify access token
	accessTokenClaims, err := s.tokenMaker.Verify(req.AccessToken)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		log.Println("Error validating access token:", err)
		return
	}

	//Get session from the storage and check if its valid
	session, err := s.storage.GetSession(r.Context(), accessTokenClaims.ID)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Println("Error getting session from db", err)
		return
	}

	//Verify refresh token
	if err := bcrypt.CompareHashAndPassword([]byte(session.RefreshToken), []byte(req.RefreshToken)); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if session.IsRevoked || time.Unix(session.ExpiresAt, 0).Before(time.Now()) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	//Revoke refresh token to prevent future use
	if err := s.storage.RevokeSession(r.Context(), session.Id); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Println("Error revoking refresh token", err)
		return
	}

	//If IP address has changed notify the user on email
	if r.RemoteAddr != session.IPAddress {
		//Hardcoded address for simplification
		//Run in a seperate goroutine to not increase latency
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			if err := sendEmail("kdnuriev@gmail.com"); err != nil {
				log.Println("Error sending email")
			}
		}()
	}

	//Create new pair of tokens
	userId := accessTokenClaims.Subject
	accessToken, refreshToken, err := s.createPairTokens(r.Context(), userId, r.RemoteAddr)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Println("Error creating tokens:", err)
		return
	}

	//Create a json object from tokens
	response, err := json.Marshal(token.TokensPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Println("Error marshaling json:", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(response); err != nil {
		log.Println("Error writing a response")
	}
}

// createPairTokens generates an access and a refresh token
func (s *AuthService) createPairTokens(ctx context.Context, userId, ipAddress string) (accessToken, refreshToken string, err error) {
	//Generate access JWT token
	tokenId := uuid.New().String()
	accessToken, accessTokenClaims, err := s.tokenMaker.NewAccessToken(tokenId, userId, ipAddress)
	if err != nil {
		return
	}

	//Generate refresh token
	refreshToken, ttl := token.NewRefreshToken()

	//Hash refresh token using bcrypt to store it in the database
	hash, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	if err != nil {
		return
	}
	//Save session to the database
	err = s.storage.SaveSession(ctx, &store.Session{
		Id:           tokenId,
		RefreshToken: string(hash),
		IPAddress:    accessTokenClaims.IPAddress,
		IsRevoked:    false,
		ExpiresAt:    ttl.Unix(),
	})
	return
}

// sendEmail will always return error since mock data is used
func sendEmail(addr string) error {
	from := "JohnDoe@mail.ru"
	password := "Mz08m4rgrwpxHHrgAdCJ"
	to := []string{addr}
	host := "smtp.mail.ru"
	port := "587"
	address := host + ":" + port
	message := []byte(fmt.Sprintf("Hey user %s, someone accessed your account from a new IP address", addr))
	auth := smtp.PlainAuth("", from, password, host)
	return smtp.SendMail(address, auth, from, to, message)
}

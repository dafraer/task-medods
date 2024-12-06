package service

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"task/store"
	"task/token"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	testSigningKey = "very_secret_key"
)

func TestHandleGenerate(t *testing.T) {
	//Create a new service for testing
	s, err := New(testSigningKey, store.NewMockStore())
	assert.NoError(t, err)

	//Create test server
	server := httptest.NewServer(http.HandlerFunc(s.handleGenerate))
	resp, err := http.Get(server.URL + "?id=1")
	assert.NoError(t, err)
	defer resp.Body.Close()

	//Check that status code is OK
	assert.Equal(t, resp.StatusCode, http.StatusOK, fmt.Sprintf("expected 200 but got %d", resp.StatusCode))

	//Decode json response into TokenPair struct
	var response token.TokensPair
	assert.NoError(t, json.NewDecoder(resp.Body).Decode(&response))

	//Check if tokens have been recieved
	assert.NotEmpty(t, response.AccessToken, "response doesn't contain an access token")
	assert.NotEmpty(t, response.RefreshToken, "response doesn't contain a refresh token")
}

func TestHandleRefresh(t *testing.T) {
	//Create a new service for testing
	s, err := New(testSigningKey, store.NewMockStore())
	assert.NoError(t, err)

	//Create test server
	generateServer := httptest.NewServer(http.HandlerFunc(s.handleGenerate))
	generateResponse, err := http.Get(generateServer.URL + "?id=1")
	assert.NoError(t, err)

	//Check ststus code
	assert.Equal(t, generateResponse.StatusCode, http.StatusOK, fmt.Sprintf("expected 200 but got %d", generateResponse.StatusCode))

	//Decode json response into TokenPair struct
	var generateResponseStruct token.TokensPair
	assert.NoError(t, json.NewDecoder(generateResponse.Body).Decode(&generateResponseStruct))

	//Check if tokens have been recieved
	assert.NotEmpty(t, generateResponseStruct.AccessToken, "response doesn't contain an access token")
	assert.NotEmpty(t, generateResponseStruct.RefreshToken, "response doesn't contain a refresh token")
	generateResponse.Body.Close()
	generateServer.Close()

	//Create test server to reresh tokens
	refreshServer := httptest.NewServer(http.HandlerFunc(s.handleRefresh))

	//Encode tokens from previous request into json
	requestBody, err := json.Marshal(generateResponseStruct)
	assert.NoError(t, err)

	//Make a request
	refreshResponse, err := http.Post(refreshServer.URL, "application/json", bytes.NewReader(requestBody))
	assert.NoError(t, err)
	defer refreshResponse.Body.Close()

	//Check that status code is OK
	assert.Equal(t, refreshResponse.StatusCode, http.StatusOK, fmt.Sprintf("expected 200 but got %d", generateResponse.StatusCode))

	//Decode json response into TokenPair struct
	var refreshResponseStruct token.TokensPair
	assert.NoError(t, json.NewDecoder(refreshResponse.Body).Decode(&refreshResponseStruct))

	//Check if tokens have been recieved
	assert.NotEmpty(t, refreshResponseStruct.AccessToken, "response doesn't contain an access token")
	assert.NotEmpty(t, refreshResponseStruct.RefreshToken, "response doesn't contain a refresh token")
}

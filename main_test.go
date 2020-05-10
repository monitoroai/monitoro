package main

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func GenerateJWT() (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)

	claims := token.Claims.(jwt.MapClaims)

	claims["authorized"] = true

	tokenString, err := token.SignedString([]byte(os.Getenv("MONITORO_SECRET_KEY")))

	if err != nil {
		fmt.Errorf("Something Went Wrong: %s", err.Error())
		return "", err
	}

	return tokenString, nil
}

func createTestFile(name string) {
	f, _ := os.Create(name)
	f.WriteString("new line\nnew line\n\n")
	f.Sync()
}

func TestHandler(t *testing.T) {
	testfile := "tests/file.log"
	createTestFile(testfile)

	buffer := Buffer{data: make([]string, 0)}
	req, err := http.NewRequest("GET", "/", nil)
	token, err := GenerateJWT()
	req.Header.Add("Token", token)

	if err != nil {
		t.Fatal(err)
	}

	go buffer.parseLogs(testfile)
	time.Sleep(1000 * time.Millisecond)

	// response recorder mocks http.ResponseWriter
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(buffer.HomeHandler)

	handler.ServeHTTP(rr, req)
	if status := rr.Code; status != 201 {
		t.Errorf("wrong status code, expected %v got %v", rr.Code, http.StatusOK)
	}

	expectedResponse := "[\"new line\",\"new line\",\"\"]\n"
	response := rr.Body.String()
	if response != expectedResponse {
		t.Errorf("wrong response, expected %s got %s", expectedResponse, response)
	}
}

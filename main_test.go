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

func TestHandler(t *testing.T) {
	buffer := Buffer{data: make([]string, 0)}
	req, err := http.NewRequest("GET", "/", nil)
	token, err := GenerateJWT()
	req.Header.Add("Token", token)

	if err != nil {
		t.Fatal(err)
	}

	go buffer.parseLogs("tests/file.log")
	time.Sleep(100 * time.Millisecond)

	// response recorder mocks http.ResponseWriter
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(buffer.HomeHandler)

	handler.ServeHTTP(rr, req)
	if status := rr.Code; status != 201 {
		t.Errorf("wrong status code, expected %v got %v", rr.Code, http.StatusOK)
	}

	expectedResponseW := "[\"new line\\r\",\"new line\\r\",\"\\r\"]\n"
	expectedResponsel := "[\"new line\",\"new line\",\"\"]"
	response := rr.Body.String()
	if response != expectedResponseW && response != expectedResponsel {
		t.Errorf("wrong response, expected %s got %s", expectedResponseW, response)
	}
}

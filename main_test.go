package main

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"os"
	"testing"
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

func TestFormatDiscovery(t *testing.T) {
	files := map[string]string{
		"tests/apache.log":          "%{COMMONAPACHELOG}",
		"tests/apache_combined.log": "%{COMBINEDAPACHELOG}",
		"tests/common_log.log":      "%{COMMONAPACHELOG}",
		"tests/file.log":            "%{UNKNOWNFORMAT}",
	}
	for logfile, expFmt := range files {
		recFmt, err := FormatDiscovery(logfile)

		if err != nil {
			t.Errorf("Error during format discovery with file: %s", logfile)
		}

		if expFmt != recFmt {
			t.Errorf("Wrong format discovered for file: %s, expected: %s but got: %s",
				logfile, expFmt, recFmt)
		}
	}
}

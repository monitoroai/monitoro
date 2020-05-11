package main

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func isAuthorized(r *http.Request, secret string) bool {
	if r.Header["Token"] != nil {

		token, err := jwt.Parse(r.Header["Token"][0], func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("bad token")
			}
			return secret, nil
		})

		if err != nil {
			return false
		}

		if token.Valid {
			return true
		} else {
			return false
		}
	} else {
		return false
	}
}

func MockHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthorized(r, os.Getenv("MONITORO_SECRET_KEY")) {
		fmt.Errorf("Bad key")
		return
	}

}

func testEndToEnd(t *testing.T) {
	handler := http.HandlerFunc(MockHandler)
	server := httptest.NewServer(handler)
	print(server.URL)
}

// TestFormatDiscovery makes sure the right format is
// discovered for supported log format (at the moment:
// apache common and combined)
func TestFormatDiscovery(t *testing.T) {
	files := map[string]string{
		"tests/apache.log":          "%{COMMONAPACHELOG}",
		"tests/apache_combined.log": "%{COMBINEDAPACHELOG}",
		"tests/common_log.log":      "%{COMMONAPACHELOG}",
		"tests/file.log":            "%{UNKNOWNFORMAT}",
	}
	for logfile, expFmt := range files {
		recFmt, err := PatternDiscovery(logfile)

		if err != nil {
			t.Errorf("Error during format discovery with file: %s", logfile)
		}

		if expFmt != recFmt {
			t.Errorf("Wrong format discovered for file: %s, expected: %s but got: %s",
				logfile, expFmt, recFmt)
		}
	}
}

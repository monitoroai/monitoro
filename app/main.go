package main

import (
	"fmt"
	"github.com/gorilla/mux"
	"log"
	"net/http"
	"os"

	jwt "github.com/dgrijalva/jwt-go"
)

var SigningKey = []byte(os.Getenv("MONITORO_SECRET_KEY"))

func HomeHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthorized(r) {
		fmt.Fprintf(w, "Not Authorized")
		return
	}
	fmt.Fprintf(w, "Hello World")
	fmt.Println("Endpoint Hit: homePage")

}

func isAuthorized(r *http.Request) bool {
	if r.Header["Token"] != nil {

		token, err := jwt.Parse(r.Header["Token"][0], func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("bad token")
			}
			return SigningKey, nil
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

func main() {
	fmt.Println("Starting application...")
	fmt.Println(os.Environ())
	r := mux.NewRouter()
	r.HandleFunc("/", HomeHandler)
	http.Handle("/", r)
	log.Fatal(http.ListenAndServe(":9000", nil))
}

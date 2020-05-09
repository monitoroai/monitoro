package main

import (
	"encoding/json"
	"fmt"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/hpcloud/tail"
	"net/http"
	"os"
	"sync"
)

var SigningKey = []byte(os.Getenv("MONITORO_SECRET_KEY"))

type Buffer struct {
	sync.Mutex
	data []string
}

// Opens a stream to a log file and continuously sends the parsed
// lines to a buffer
func (buffer *Buffer) parseLogs(logfile string) {
	t, err := tail.TailFile(logfile, tail.Config{Follow: true})

	if err != nil {
		fmt.Errorf("error reading log file %s", err)
	}

	for line := range t.Lines {
		fmt.Println(line.Text)
		buffer.Lock()
		buffer.data = append(buffer.data, line.Text)
		buffer.Unlock()
	}
}

// Checks if the token is valid, returns the buffer and
// re-initialize it to an array of size 0
func (buffer *Buffer) HomeHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthorized(r) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("403 - Not Authorized"))
		return
	}
	fmt.Println("Endpoint Hit: homePage")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)

	buffer.Lock()
	json.NewEncoder(w).Encode(buffer.data)
	buffer.data = make([]string, 0)
	buffer.Unlock()
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
	fmt.Println("Starting parser...")
	buffer := Buffer{data: make([]string, 0)}

	go buffer.parseLogs("file.log")

	fmt.Println("Starting application...")
	r := mux.NewRouter()
	r.HandleFunc("/", buffer.HomeHandler)
	http.Handle("/", r)
	http.ListenAndServe(":9000", nil)
}

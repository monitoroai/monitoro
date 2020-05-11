package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/hpcloud/tail"
	"github.com/trivago/grok"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"sync"
)

type Buffer struct {
	sync.Mutex
	data []map[string]string
}

func GenerateJWT(secret string) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)

	claims := token.Claims.(jwt.MapClaims)

	claims["authorized"] = true

	tokenString, err := token.SignedString([]byte(secret))

	if err != nil {
		fmt.Errorf("Something Went Wrong: %s\n", err.Error())
		return "", err
	}

	return tokenString, nil
}

// Compare one line of a log file against
// some popular formats using grok. If it finds
// a matching format it returns it
func findPattern(line string) (string, error) {
	stdPatterns := []string{
		"%{COMBINEDAPACHELOG}",
		"%{COMMONAPACHELOG}",
	}
	g, err := grok.New(grok.Config{NamedCapturesOnly: true})
	if err != nil {
		fmt.Printf("Error when creating new Grok object\n")
		return "", err
	}
	for _, pattern := range stdPatterns {
		r, err := g.MatchString(pattern, line)
		if err != nil {
			fmt.Printf("Error trying to match format: %s with line: %s", pattern, line)
			return "", err
		}
		if r {
			return pattern, nil
		}
	}
	return "%{UNKNOWNFORMAT}", nil
}

// Compare one line of a log file with the
// most standard log formats. If it finds a matching format
// it returns it, else it tries to extract standard fields
// individually, if it fails it returns an error
func PatternDiscovery(logfile string) (string, error) {
	f, err := os.Open(logfile)
	if err != nil {
		fmt.Printf("Error when opening file: %s", logfile)
		return "", err
	}

	defer func() {
		if err := f.Close(); err != nil {
			panic(err)
		}
	}()

	reader := bufio.NewReader(f)
	line, _, err := reader.ReadLine()

	if err != nil {
		fmt.Printf("Error when reading file: %s", logfile)
	}

	pattern, err := findPattern(string(line))

	if err != nil {
		fmt.Printf("Error finding format with line: %s\n", line)
		return "", err
	}
	return pattern, nil
}

// Concurrently parse each line of the logs in
// the format discovered by FormatDiscovery
func (buffer *Buffer) parseLines(t *tail.Tail, cg *grok.CompiledGrok) {
	for line := range t.Lines {
		buffer.Lock()
		fields := cg.ParseString(line.Text)
		buffer.data = append(buffer.data, fields)
		if len(buffer.data) == 500 {
			reqBody, _ := json.Marshal(buffer.data)
			req, err := http.NewRequest("POST", "http://127.0.0.1:9000/", bytes.NewBuffer(reqBody))

			if err != nil {
				log.Fatalln(err)
			}

			defer req.Body.Close()
			body, err := ioutil.ReadAll(req.Body)

			if err != nil {
				log.Fatalln(err)
			}
			log.Println(string(body))
		}
		buffer.Unlock()
	}
}

func main() {
	// Number of concurrent parser
	//n := 10
	//secret := os.Getenv("MONITORO_SECRET_KEY")
	logfile := "tests/apache.log"

	pattern, _ := PatternDiscovery(logfile)
	if pattern == "%{UNKNOWNPATTERN}" {
		fmt.Errorf("Unknown pattern with file: %s\n", logfile)
	}

	t, _ := tail.TailFile(logfile, tail.Config{Follow: true})
	g, _ := grok.New(grok.Config{})
	cg, _ := g.Compile(pattern)
	print(pattern)

	// Parse lines of the log file and store them in buffer
	buffer := Buffer{data: make([]map[string]string, 0)}
	//for i := 0; i < n; i++ {
	//	go buffer.parseLines(t, cg)
	//}
	buffer.parseLines(t, cg)
}

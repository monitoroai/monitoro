package main

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"net/http"
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

func Map(vs []map[string]string, f func(map[string]string) bool) []bool {
	vsm := make([]bool, len(vs))
	for i, v := range vs {
		vsm[i] = f(v)
	}
	return vsm
}

func contains(arr [3]string, str string) bool {
	for _, a := range arr {
		if a == str {
			return true
		}
	}
	return false
}

func assertReqFields(fields map[string]string) bool {
	reqFields := []string{"verb", "IP", "response", "request", "timestamp"}
	for _, f := range reqFields {
		if _, ok := fields[f]; !ok {
			return false
		}
	}
	return true
}

//func TestEndToEnd(t *testing.T) {
//	files := map[string]string{
//		"tests/apache.log":          "%{COMMONAPACHELOG}",
//		"tests/apache_combined.log": "%{COMBINEDAPACHELOG}",
//		"tests/common_log.log":      "%{COMMONAPACHELOG}",
//	}
//	for file, pattern := range files {
//		t.Run("end-to-end_"+file, func(t *testing.T) {
//			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//				body, err := ioutil.ReadAll(r.Body)
//				if err != nil {
//					t.Error(err)
//				}
//				var data []map[string]string
//
//				if err := json.Unmarshal(body, &data); err != nil {
//					t.Error(err)
//				}
//				if len(data) != 1000 {
//					t.Error(err)
//				}
//				for _, b := range Map(data, assertReqFields) {
//					if !b {
//						t.Error()
//					}
//				}
//			}))
//
//			tf, err := tail.TailFile(file, tail.Config{Follow: true})
//			if err != nil {
//				t.Error(err)
//			}
//			g, err := grok.New(grok.Config{})
//			if err != nil {
//				t.Error(err)
//			}
//			cg, err := g.Compile(pattern)
//			if err != nil {
//				t.Error(err)
//			}
//			buffer := Buffer{data: make(chan map[string]string, 0), url: ts.URL}
//			buffer.parseLines(tf, cg, 1000)
//			time.Sleep(10000 * time.Millisecond)
//			err = tf.Stop()
//			if err != nil {
//				t.Error(err)
//			}
//			defer ts.Close()
//		})
//	}
//}

// TestPatternDiscovery makes sure the right pattern is
// discovered for supported log patterns (at the moment:
// apache common and combined)
func TestPatternDiscovery(t *testing.T) {
	files := map[string]string{
		"tests/apache.log":          "%{COMMONAPACHELOG}",
		"tests/apache_combined.log": "%{COMBINEDAPACHELOG}",
		"tests/common_log.log":      "%{COMMONAPACHELOG}",
		"tests/file.log":            "%{UNKNOWNPATTERN}",
	}
	for logfile, expPattern := range files {
		t.Run("pattern-discovery_"+logfile, func(t *testing.T) {
			recPattern, _, err := PatternDiscovery(logfile, "")

			if err != nil {
				t.Errorf("Error during format discovery with file: %s", logfile)
			}

			if expPattern != recPattern {
				t.Errorf("Wrong format discovered for file: %s, expected: %s but got: %s",
					logfile, expPattern, recPattern)
			}
		})
	}
}

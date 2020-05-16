package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/akamensky/argparse"
	"github.com/dgrijalva/jwt-go"
	"github.com/hpcloud/tail"
	"github.com/robfig/cron/v3"
	"github.com/trivago/grok"
	"net/http"
	"os"
)

type Buffer struct {
	data chan map[string]string
	url  string
}

func readHead(file string) ([]byte, error) {
	f, err := os.Open(file)
	if err != nil {
		fmt.Printf("could not read file: %s", file)
	}

	defer func() {
		if err := f.Close(); err != nil {
			panic(err)
		}
	}()

	reader := bufio.NewReader(f)
	line, _, err := reader.ReadLine()
	return line, err
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
// some popular formats using grok and return the format found
func findPattern(line string, customPattern string) (string, grok.Config, error) {
	c := grok.Config{}
	patterns := []string{"%{COMBINEDAPACHELOG}", "%{COMMONAPACHELOG}"}
	if customPattern != "" {
		patterns = append(patterns, "%{CUSTOMPATTERN}")
	}

	for _, pattern := range patterns {
		if pattern == "%{CUSTOMPATTERN}" {
			c.Patterns = map[string]string{"CUSTOMPATTERN": customPattern}
			c.NamedCapturesOnly = true
		}
		g, err := grok.New(c)
		if err != nil {
			fmt.Printf("Error when creating new Grok object\n")
			return "", c, err
		}
		r, err := g.MatchString(pattern, line)
		if err != nil {
			fmt.Printf("Error trying to match format: %s with line: %s", pattern, line)
			return "", c, err
		}
		if r {
			return pattern, c, nil
		}
	}
	return "%{UNKNOWNPATTERN}", c, nil
}

// Compare one line of a log file with the
// most standard log formats. If it finds a matching format
// it returns it, else it tries to extract standard fields
// individually, if it fails it returns an error
func PatternDiscovery(logfile string, customPattern string) (string, grok.Config, error) {
	line, err := readHead(logfile)
	if err != nil {
		fmt.Printf("Error when reading file: %s", logfile)
	}

	pattern, c, err := findPattern(string(line), customPattern)
	if err != nil {
		fmt.Printf("Error finding format with line: %s\n", line)
		return "", c, err
	}
	return pattern, c, nil
}

// Reads all the content in the channel at once and send the
// data as a POST request to the given url
func sendData(url string, ch chan map[string]string) error {
	data := make([]map[string]string, len(ch))
	for len(ch) > 0 {
		d := <-ch
		data = append(data, d)
	}
	reqBody, _ := json.Marshal(data)
	_, err := http.Post(url, "application/json", bytes.NewBuffer(reqBody))
	return err
}

// Concurrently parse each line of the logs in
// the format discovered by FormatDiscovery
func (buffer *Buffer) parseLines(t *tail.Tail, cg *grok.CompiledGrok, size int) {
	for line := range t.Lines {
		fields := cg.ParseString(line.Text)
		buffer.data <- fields
		if len(buffer.data) == size {
			buffer.emptyBuffer()
		}
	}
}

func (buffer *Buffer) emptyBuffer() {
	err := sendData(buffer.url, buffer.data)
	if err != nil {
		fmt.Println(err)
	}
}

func main() {
	parser := argparse.NewParser("Monitoro", "Client for Monitoro's intrusion detection system.")
	path := parser.String("p", "path", &argparse.Options{
		Required: true,
		Help: "Path of the log file to parse. Depending on your os you should find it" +
			"in either /var/log/apache/access.log, /var/log/apache2/access.log or /etc/httpd/logs/access_log.",
	})
	size := parser.Int("s", "size", &argparse.Options{
		Required: false,
		Help:     "Maximal number of lines of log the buffer can hold in memory before sending them to Monitoro.",
		Default:  100,
	})
	schedule := parser.String("", "schedule", &argparse.Options{
		Required: false,
		Help:     "Cron expression for scheduling the time when logs are sent to Monitoro.",
		Default:  "@every 10m",
	})
	pattern := parser.String("", "pattern", &argparse.Options{
		Required: false,
		Help: "If your logs are customized or you're not using apache, you can specify your pattern here. " +
			"We support all of Grok's format, check out https://logz.io/blog/logstash-grok/ for more information.",
		Default: nil,
	})
	threads := parser.Int("n", "threads", &argparse.Options{
		Required: false,
		Help: "Number of concurrent parsers. Depending on your application you might need more or less threads " +
			"to parse all your logs in a reasonable amount of time.",
		Default: 2,
	})
	apiURL := parser.String("", "url", &argparse.Options{
		Required: false,
		Help:     "URL of the server where you want to send the logs to. Defaults to Monitoro's official API server.",
		Default:  "http://127.0.0.1:9000/",
	})

	err := parser.Parse(os.Args)
	if err != nil {
		fmt.Print(parser.Usage(err))
	}

	//secret := os.Getenv("MONITORO_SECRET_KEY")
	p, gc, err := PatternDiscovery(*path, *pattern)
	if err != nil || p == "%{UNKNOWNPATTERN}" {
		fmt.Println("error finding pattern, use the --pattern flag if you want to use a custom pattern")
	}

	g, err := grok.New(gc)
	if err != nil {
		fmt.Println("unable to build grok expression")
	}

	t, err := tail.TailFile(*path, tail.Config{Follow: true, MustExist: true, Poll: true})
	if err != nil {
		fmt.Printf("error tailing file %s\n", *path)
	}
	cg, err := g.Compile(p)
	if err != nil {
		fmt.Printf("error compiling grok expression with pattern: %s", p)
	}

	// Parse lines of the log file and store them in buffer
	buffer := Buffer{data: make(chan map[string]string, *size), url: *apiURL}
	for i := 0; i < *threads; i++ {
		go buffer.parseLines(t, cg, *size)
	}
	//go buffer.parseLines(t, cg, *size)
	// Cron job for emptying the buffer
	c := cron.New()
	_, _ = c.AddFunc(*schedule, buffer.emptyBuffer)
	c.Start()

	<-make(chan int)
}

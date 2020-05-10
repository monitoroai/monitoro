package main

import (
	"bufio"
	"fmt"
	"github.com/hpcloud/tail"
	"github.com/trivago/grok"
	"os"
	"sync"
)

type Buffer struct {
	sync.Mutex
	data []string
}

// Compare one line of a log file against
// some popular formats using grok. If it finds
// a matching format it returns it
func findFormat(line string) (string, error) {
	stdFormat := []string{
		"%{COMBINEDAPACHELOG}",
		"%{COMMONAPACHELOG}",
	}
	g, err := grok.New(grok.Config{NamedCapturesOnly: true})
	if err != nil {
		fmt.Printf("Error when creating new Grok object\n")
		return "", err
	}
	for _, f := range stdFormat {
		r, err := g.MatchString(f, line)
		if err != nil {
			fmt.Printf("Error trying to match format: %s with line: %s", f, line)
			return "", err
		}
		if r {
			return f, nil
		}
	}
	return "%{UNKNOWNFORMAT}", nil
}

// Compare one line of a log file with the
// most standard log formats. If it finds a matching format
// it returns it, else it tries to extract standard fields
// individually, if it fails it returns an error
func FormatDiscovery(logfile string) (string, error) {
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

	format, err := findFormat(string(line))

	if err != nil {
		fmt.Printf("Error finding format with line: %s\n", line)
		return format, err
	}
	return format, nil
}

// Concurrently process each line of the logs
func (buffer *Buffer) parseLines(t *tail.Tail, i int) {
	for line := range t.Lines {
		buffer.Lock()
		buffer.data = append(buffer.data, line.Text)
		buffer.Unlock()
	}
}

func main() {
	f, _ := FormatDiscovery("tests/apache.log")
	print(f)
}

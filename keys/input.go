package keys

import (
	"bufio"
	"github.com/luastan/keytest/kt"
	"github.com/luastan/keytest/logger"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
)

const BuffSize = 512 * 1024

func PathsToInputHandles(paths <-chan string) <-chan InputHandle {
	ch := make(chan InputHandle, 1)
	go func() {
		defer close(ch)
		for path := range paths {
			f, err := os.Open(path)
			if err == nil {
				ch <- InputHandle{File: path, Reader: bufio.NewReader(f), descriptor: f}
			} else {
				logger.ErrorLogger.Println(err.Error())
			}
		}
	}()
	return ch
}

// InputHandlesFromStdin returns a channel that will only receive the stdin
// InputHandle
func InputHandlesFromStdin() <-chan InputHandle {
	ch := make(chan InputHandle)
	go func() {
		defer close(ch)
		ch <- InputHandle{File: "stdin", Reader: os.Stdin}
	}()

	return ch
}

// ReadersToLines Returns every line from an InputHandle through a chanel
func ReadersToLines(inputHandles <-chan InputHandle) <-chan *Line {
	ch := make(chan *Line)
	go func() {
		defer close(ch)
		var wg sync.WaitGroup

		for i := 0; i < *kt.Workers; i++ {
			wg.Add(1)
			go func(handles <-chan InputHandle) {
				defer wg.Done()
				for handle := range handles {
					sc := bufio.NewScanner(handle.Reader)
					sc.Buffer(make([]byte, BuffSize), BuffSize)
					sc.Split(bufio.ScanLines)
					for i := 1; sc.Scan(); i++ {
						ch <- &Line{Location: &Location{File: handle.File, Line: i}, Content: sc.Text()}
					}
					handle.close()
				}
			}(inputHandles)
		}
		wg.Wait()
	}()

	return ch
}

// Files returns a channel with all the paths with files to parse
func Files(paths []string) <-chan string {
	ch := make(chan string, 10)
	go func() {
		defer close(ch)
		for _, providedPath := range paths {
			_ = filepath.Walk(providedPath, func(path string, info fs.FileInfo, err error) error {
				if err == nil && !info.IsDir() {
					ch <- path
				}
				return nil
			})
		}
	}()
	return ch
}

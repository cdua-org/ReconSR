package cli

import (
	"bufio"
	"os"
	"strings"
	"sync"
)

var (
	sharedInputChan chan string
	initInputOnce   sync.Once
)

func getSharedInput() <-chan string {
	initInputOnce.Do(func() {
		sharedInputChan = make(chan string)
		go func() {
			scanner := bufio.NewScanner(os.Stdin)
			for scanner.Scan() {
				sharedInputChan <- strings.TrimSpace(scanner.Text())
			}
		}()
	})
	return sharedInputChan
}

func readUserInput() string {
	return <-getSharedInput()
}

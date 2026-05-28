package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"

	"cdua-org/ReconSR/internal/controller"
	"cdua-org/ReconSR/internal/i18n"
)

// InteractiveControl listens for terminal input to pause, resume, or stop execution.
func InteractiveControl(ctx context.Context, done <-chan struct{}) {
	ttyPath := "/dev/tty"
	if runtime.GOOS == "windows" {
		ttyPath = "CONIN$"
	}

	tty, err := os.Open(ttyPath)
	if err != nil {
		<-done
		return
	}
	defer tty.Close()

	inputChan := make(chan string)
	go func() {
		scanner := bufio.NewScanner(tty)
		for scanner.Scan() {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case inputChan <- strings.TrimSpace(scanner.Text()):
			}
		}
	}()

	isPaused := false

	for {
		select {
		case <-done:
			return
		case <-ctx.Done():
			return
		case input := <-inputChan:
			switch input {
			case "0":
				os.Exit(0)
			case "1":
				isPaused = !isPaused
				if isPaused {
					controller.PauseRecon()
				} else {
					controller.ResumeRecon()
				}
			default:
				fmt.Println(colorRed + i18n.T["ERR_INVALID_CHOICE"] + colorReset)
			}

			if isPaused {
				fmt.Println("\n" + colorYellow + colorBold + i18n.T["MSG_RECON_PAUSED"] + colorReset)
			} else {
				fmt.Println("\n" + colorCyan + colorBold + i18n.T["MSG_RECON_STARTED"] + colorReset)
			}
		}
	}
}

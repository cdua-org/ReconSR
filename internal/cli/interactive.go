package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"

	"cdua-org/ReconSR/internal/controller"
	"cdua-org/ReconSR/internal/i18n"
	"cdua-org/ReconSR/internal/report"
)

// InteractiveControl listens for terminal input to pause, resume, or stop execution.
func InteractiveControl(ctx context.Context, done <-chan struct{}) {
	ttyPath := getTTYPath()
	openFlags := getTTYOpenFlags()

	tty, err := os.OpenFile(ttyPath, openFlags, 0)
	if err != nil {
		tty, err = os.Open(ttyPath)
		if err != nil {
			<-done
			return
		}
	}
	defer tty.Close()

	inputChan := make(chan string)
	go func() {
		buf := make([]byte, 128)
		var currentLine string
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			default:
			}

			_ = tty.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			n, err := tty.Read(buf)
			if n > 0 {
				for _, ch := range string(buf[:n]) {
					if ch == '\n' || ch == '\r' {
						val := strings.TrimSpace(currentLine)
						if val != "" {
							select {
							case inputChan <- val:
							case <-done:
								return
							case <-ctx.Done():
								return
							}
						}
						currentLine = ""
					} else {
						currentLine += string(ch)
					}
				}
			}

			if err != nil {
				if os.IsTimeout(err) || errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
					time.Sleep(200 * time.Millisecond)
					continue
				}
				return
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
			case "2":
				printProjectStats(ctx)
			case "3":
				graph, err := controller.GetActiveGraph(ctx, false)
				if err != nil {
					fmt.Printf("%s: %v\n", i18n.T["LBL_ERROR"], err)
				} else {
					report.RenderResultsTree(graph)
				}
			case "4":
				graph, err := controller.GetActiveGraph(ctx, true)
				if err != nil {
					fmt.Printf("%s: %v\n", i18n.T["LBL_ERROR"], err)
				} else {
					filename, err := report.GenerateHTML(ctx, graph)
					if err != nil {
						fmt.Printf("%s: %v\n", i18n.T["LBL_ERROR"], err)
					} else {
						fmt.Printf("\n%s: %s\n", i18n.T["MSG_REPORT_SAVED"], filename)
					}
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

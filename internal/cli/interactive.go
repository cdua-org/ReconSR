package cli

import (
	"context"
	"fmt"
	"os"

	"cdua-org/ReconSR/internal/controller"
	"cdua-org/ReconSR/internal/i18n"
	"cdua-org/ReconSR/internal/report"
)

func printReconStatus(isPaused bool) {
	msg := i18n.T["MSG_RECON_STARTED"]
	opt1 := i18n.T["OPT_PAUSE"]
	c := colorCyan
	if isPaused {
		msg = i18n.T["MSG_RECON_PAUSED"]
		opt1 = i18n.T["OPT_RESUME"]
		c = colorYellow
	}

	fmt.Printf("\n%s%s%s [1] %s | [2] %s | [3] %s | [4] %s | [5] %s | [0] %s%s\n",
		c, colorBold, msg,
		opt1,
		i18n.T["OPT_STATS"],
		i18n.T["OPT_SHORT_TREE"],
		i18n.T["OPT_SHORT_TREE_HTML"],
		i18n.T["OPT_SHORT_GRAPH"],
		i18n.T["OPT_EXIT"],
		colorReset)
}

// InteractiveControl listens for terminal input to pause, resume, or stop execution.
func InteractiveControl(ctx context.Context, done <-chan struct{}) {
	isPaused := false

	for {
		select {
		case <-done:
			return
		case <-ctx.Done():
			return
		case input := <-getSharedInput():
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
					report.RenderResultsTree(os.Stdout, graph, &report.ConsoleTreeFormatter{})
				}
			case "4":
				graph, err := controller.GetActiveGraph(ctx, false)
				if err != nil {
					fmt.Printf("%s: %v\n", i18n.T["LBL_ERROR"], err)
				} else {
					filename, err := report.GenerateTreeHTML(graph)
					if err != nil {
						fmt.Printf("%s: %v\n", i18n.T["LBL_ERROR"], err)
					} else {
						fmt.Printf("\n%s: %s\n", i18n.T["MSG_REPORT_SAVED"], filename)
					}
				}
			case "5":
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

			printReconStatus(isPaused)
		}
	}
}

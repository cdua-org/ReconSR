package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	"cdua-org/ReconSR/internal/boot"
	"cdua-org/ReconSR/internal/cli"
	"cdua-org/ReconSR/internal/pipeline"
	"cdua-org/ReconSR/internal/updater"
)

func main() {
	ctx := context.Background()

	if len(os.Args) > 1 && os.Args[1] == "update" {
		client := &http.Client{
			Timeout: 30 * time.Second,
		}
		if err := updater.Update(ctx, client, cli.AppVersion); err != nil {
			log.Fatalf("Update error: %v", err)
		}
		os.Exit(0)
	}

	if err := boot.Init(ctx, "lang/en.txt"); err != nil {
		log.Fatalf("Initialization error: %v", err)
	}

	cli.ShowBanner(ctx)
	rawTarget := cli.GetRawTarget(ctx, os.Args)

	for cli.HandleUserInput(ctx, rawTarget) {
		done := make(chan struct{})
		go func() {
			pipeline.Run(ctx)
			close(done)
		}()

		cli.InteractiveControl(ctx, done)
		cli.ShowReconCompleteBanner(ctx)
	}
}

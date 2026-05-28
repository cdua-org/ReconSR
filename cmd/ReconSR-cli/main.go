package main

import (
	"context"
	"log"
	"os"

	"cdua-org/ReconSR/internal/boot"
	"cdua-org/ReconSR/internal/cli"
	"cdua-org/ReconSR/internal/pipeline"
)

func main() {
	ctx := context.Background()

	if err := boot.Init(ctx, "lang/en.txt"); err != nil {
		log.Fatalf("Initialization error: %v", err)
	}

	cli.ShowBanner(ctx)
	rawTarget := cli.GetRawTarget(os.Args)

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

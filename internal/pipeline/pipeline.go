package pipeline

import (
	"context"
	"log"
	"sync"

	"cdua-org/ReconSR/internal/controller"
	"cdua-org/ReconSR/internal/dispatcher"
	"cdua-org/ReconSR/internal/processor"
	"cdua-org/ReconSR/internal/repository"
	"cdua-org/ReconSR/internal/scopemanager"
	"cdua-org/ReconSR/schema"
)

// Run initializes the channels and waitgroups, routing the data through the system.
func Run(ctx context.Context) {
	if err := scopemanager.Load(ctx); err != nil {
		log.Printf("Warning: failed to load scope: %v", err)
	}

	injection := controller.GetInjection()
	if injection == nil {
		return
	}

	repoChan := make(chan *schema.ProcessorToRepoData)
	dispatchChan := make(chan *schema.RepoToDispatcherData)
	var wg sync.WaitGroup
	var repoWritersWg sync.WaitGroup

	if injection.ToProcessor != nil {
		wg.Add(1)
		repoWritersWg.Add(1)
		go func() {
			defer wg.Done()
			processor.Process(injection.ToProcessor, repoChan, &repoWritersWg)
		}()
	} else if injection.ToDispatcher != nil && len(injection.ToDispatcher.Batch) > 0 {
		wg.Add(1)
		repoWritersWg.Add(len(injection.ToDispatcher.Batch))
		go func() {
			defer wg.Done()
			dispatchChan <- injection.ToDispatcher
		}()
	}

	go func() {
		repoWritersWg.Wait()
		close(repoChan)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(dispatchChan)
		for packet := range repoChan {
			expectedTokens := 0
			for _, group := range packet.Groups {
				expectedTokens += len(group.Results)
			}

			repoData, err := repository.Store(ctx, packet)

			actualTokens := 0
			if err == nil && repoData != nil {
				actualTokens = len(repoData.Batch)
			}

			if expectedTokens > actualTokens {
				repoWritersWg.Add(-(expectedTokens - actualTokens))
			}

			if err != nil {
				log.Printf("Data storage error: %v", err)
				continue
			}
			if repoData != nil {
				dispatchChan <- repoData
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for res := range dispatchChan {
			dispatcher.Dispatch(res, repoChan, &repoWritersWg)
		}
	}()

	wg.Wait()
}

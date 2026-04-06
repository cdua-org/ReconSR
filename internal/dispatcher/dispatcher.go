package dispatcher

import (
	"cdua-org/ReconSR/internal/processor"
	"cdua-org/ReconSR/internal/repository"
	"cdua-org/ReconSR/schema"
	"context"
	"fmt"
	"sync"
	"time"
)

var (
	moduleIndex    = make(map[string][]moduleEntry)
	globalTimeout  = 2 * time.Minute
	enabledConfigs = make(map[string]map[string]bool) // map[module]map[function]bool
)

type moduleEntry struct {
	mod       schema.Module
	functions []string
}

// Init initializes the dispatcher.
func Init(ctx context.Context) error {
	return nil
}

// GetModuleSettings returns a copy of the current module configuration.
func GetModuleSettings() map[string]map[string]bool {
	copyMap := make(map[string]map[string]bool)
	for mod, fns := range enabledConfigs {
		copyMap[mod] = make(map[string]bool)
		for fn, state := range fns {
			copyMap[mod][fn] = state
		}
	}
	return copyMap
}

// SetGlobalTimeout sets the execution timeout.
func SetGlobalTimeout(d time.Duration) {
	globalTimeout = d
}

// GetGlobalTimeout returns the current execution timeout.
func GetGlobalTimeout() time.Duration {
	return globalTimeout
}

// GetAllCapabilities returns all registered module capabilities.
func GetAllCapabilities() map[string][]string {
	all := make(map[string][]string)
	for _, m := range ModuleRegistry {
		caps, err := m.Capabilities()
		if err == nil {
			all[m.Name()] = caps.Functions
		}
	}
	return all
}

// LoadConfig updates the module index and repository based on provided settings.
func LoadConfig(ctx context.Context, settings map[string]map[string]bool) error {
	cleanSettings := make(map[string]map[string]bool)
	allCaps := GetAllCapabilities()

	for mod, fns := range settings {
		validFns, exists := allCaps[mod]
		if !exists {
			continue
		}

		validFnMap := make(map[string]bool)
		for _, fn := range validFns {
			validFnMap[fn] = true
		}

		cleanSettings[mod] = make(map[string]bool)
		for fn, state := range fns {
			if validFnMap[fn] {
				cleanSettings[mod][fn] = state
			}
		}
	}

	enabledConfigs = cleanSettings
	moduleIndex = make(map[string][]moduleEntry)
	var registrations []schema.ModuleRegistration

	for _, m := range ModuleRegistry {
		caps, err := m.Capabilities()
		if err != nil {
			continue
		}
		reg := schema.ModuleRegistration{
			Name:        m.Name(),
			Caps:        caps,
			EnabledFunc: enabledConfigs[m.Name()],
		}
		registrations = append(registrations, reg)

		var activeFuncsForMod []string
		for _, fn := range caps.Functions {
			if enabledConfigs[m.Name()][fn] {
				activeFuncsForMod = append(activeFuncsForMod, fn)
			}
		}

		if len(activeFuncsForMod) > 0 {
			for _, inputType := range caps.InputTypes {
				moduleIndex[inputType] = append(moduleIndex[inputType], moduleEntry{
					mod:       m,
					functions: activeFuncsForMod,
				})
			}
		}
	}

	return repository.SyncMasterDB(ctx, registrations)
}

// Dispatch routes each entity to the appropriate modules based on type and pending functions.
func Dispatch(data *schema.RepoToDispatcherData, out chan<- *schema.ProcessorToRepoData, writersWg *sync.WaitGroup) {
	for _, item := range data.Batch {
		// Launch each entity's processing in its own goroutine to prevent head-of-line blocking
		go func(item schema.RepoToDispatcherBatchItem) {
			if item.OutOfScope {
				writersWg.Done()
				return
			}

			entries, ok := moduleIndex[item.Entity.Type]
			if !ok || len(entries) == 0 {
				writersWg.Done()
				return
			}

			// Build a set of already completed module+function pairs for O(1) lookup.
			completedSet := make(map[schema.ModuleFunction]struct{}, len(item.CompletedFunctions))
			for _, cf := range item.CompletedFunctions {
				completedSet[cf] = struct{}{}
			}

			anyDispatched := false
			var moduleResults []*schema.ProcessorInputData

			for _, entry := range entries {
				var pending []string
				for _, fn := range entry.functions {
					modFn := schema.ModuleFunction{ModuleName: entry.mod.Name(), Function: fn}
					if _, done := completedSet[modFn]; !done {
						pending = append(pending, fn)
					}
				}

				if len(pending) == 0 {
					continue
				}

				payload := schema.ModuleInput{
					Target:    item.Entity,
					Functions: pending,
				}

				// Use a channel and goroutine to implement timeout
				type modResult struct {
					res schema.ModuleOutput
					err error
				}
				resChan := make(chan modResult, 1)

				go func() {
					res, err := entry.mod.Exec(payload)
					resChan <- modResult{res, err}
				}()

				var result schema.ModuleOutput
				var execErr error
				timedOut := false

				select {
				case r := <-resChan:
					result = r.res
					execErr = r.err
				case <-time.After(globalTimeout):
					timedOut = true
				}

				if timedOut {
					var systemErrors []schema.ProcessorInputError
					timeoutMsg := fmt.Sprintf("SYSTEM: Timeout exceeded after %v", globalTimeout)
					for _, fn := range pending {
						systemErrors = append(systemErrors, schema.ProcessorInputError{
							Function: fn,
							Type:     "timeout",
							Text:     timeoutMsg,
						})
					}
					processorData := &schema.ProcessorInputData{
						ProjectID:          data.ProjectID,
						ModuleName:         entry.mod.Name(),
						SourceEntity:       item.Entity,
						RequestedFunctions: pending,
						Errors:             systemErrors,
					}
					moduleResults = append(moduleResults, processorData)
					anyDispatched = true
					continue
				}

				if execErr != nil {
					continue
				}

				// Map module executions to the unified processor input format
				var executions []schema.ProcessorInputExecution
				for _, exec := range result.Executions {
					var results []schema.ProcessorInputResult
					for _, r := range exec.Results {
						results = append(results, schema.ProcessorInputResult(r))
					}
					executions = append(executions, schema.ProcessorInputExecution{
						Function: exec.Function,
						Results:  results,
						RawData:  exec.RawData,
						Error:    exec.Error,
					})
				}

				processorData := &schema.ProcessorInputData{
					ProjectID:          data.ProjectID,
					ModuleName:         entry.mod.Name(),
					SourceEntity:       item.Entity,
					Executions:         executions,
					RequestedFunctions: pending,
				}

				moduleResults = append(moduleResults, processorData)
				anyDispatched = true
			}

			if anyDispatched {
				// Correct the counter: we have 1 unit (this entity), but we spawned K module packets.
				// So we add (K - 1).
				writersWg.Add(len(moduleResults) - 1)
				for _, pd := range moduleResults {
					go func(p *schema.ProcessorInputData) {
						processor.Process(p, out, writersWg)
					}(pd)
				}
			} else {
				writersWg.Done()
			}
		}(item)
	}
}

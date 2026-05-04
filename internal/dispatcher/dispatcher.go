package dispatcher

import (
	"cdua-org/ReconSR/internal/processor"
	"cdua-org/ReconSR/internal/repository"
	"cdua-org/ReconSR/schema"
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

var (
	// System limits (initialized with defaults, updated by config)
	GlobalMaxConcurrency      = 200 // Max total concurrent module executions
	DefaultFuncConcurrency    = 30  // Default limit if module provides none
	MaxAllowedFuncConcurrency = 100 // Hard cap to prevent greedy modules
	DefaultFuncDelayMs        = 200 // Default rate limit delay in ms
	GlobalTimeoutSeconds      = 120 // Global execution timeout in seconds
)

var (
	moduleIndex                = make(map[string][]moduleEntry)
	enabledConfigs             = make(map[string]map[string]bool)
	inFlight                   sync.Map
	dispatcherConcurrencyLimit = make(chan struct{}, GlobalMaxConcurrency)
	moduleLimits               sync.Map
	funcLimits                 = make(map[string]map[string]int)
	funcDelays                 = make(map[string]map[string]int)
	cfgFuncLimits              map[string]map[string]int
	cfgFuncDelays              map[string]map[string]int
)

type moduleLimit struct {
	sem     chan struct{}
	limit   int
	delayMs int
	mu      sync.Mutex
	lastRun int64
}

type moduleEntry struct {
	mod         schema.Module
	functions   []string
	requireTags [][]string
	excludeTags [][]string
}

func containsTag(tags []string, target string) bool {
	for _, t := range tags {
		if t == target {
			return true
		}
	}
	return false
}

func matchTags(entityTags []string, require [][]string, exclude [][]string) bool {
	if len(require) == 0 {
		return true
	}

GroupLoop:
	for i := 0; i < len(require); i++ {
		for _, tag := range require[i] {
			if !containsTag(entityTags, tag) {
				continue GroupLoop
			}
		}

		for _, tag := range exclude[i] {
			if containsTag(entityTags, tag) {
				continue GroupLoop
			}
		}

		return true
	}
	return false
}

// IsActionable checks if a specific function can be executed for an entity based on its tags.
func IsActionable(entityType, moduleName, funcName string, entityTags []string) bool {
	entries, ok := moduleIndex[entityType]
	if !ok {
		return false
	}

	for _, entry := range entries {
		if entry.mod.Name() != moduleName {
			continue
		}
		for _, f := range entry.functions {
			if f == funcName {
				return matchTags(entityTags, entry.requireTags, entry.excludeTags)
			}
		}
	}
	return false
}

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

func SetGlobalTimeout(d time.Duration) {
	GlobalTimeoutSeconds = int(d.Seconds())
}

func GetGlobalTimeout() time.Duration {
	return time.Duration(GlobalTimeoutSeconds) * time.Second
}

// GetAllCapabilities returns all registered module capabilities.
func GetAllCapabilities() map[string][]string {
	all := make(map[string][]string)
	for _, m := range ModuleRegistry {
		caps, err := m.Capabilities()
		if err == nil {
			funcSet := make(map[string]bool)

			for _, fn := range caps.Functions {
				funcSet[fn] = true
			}

			// Merge functions declared via CustomFunctions.
			for fn := range caps.CustomFunctions {
				funcSet[fn] = true
			}

			var mergedFuncs []string
			for fn := range funcSet {
				mergedFuncs = append(mergedFuncs, fn)
			}
			all[m.Name()] = mergedFuncs
		}
	}
	return all
}

// GetFuncDefaults returns per-function limit and delay computed by LoadConfig.
func GetFuncDefaults() (map[string]map[string]int, map[string]map[string]int) {
	return funcLimits, funcDelays
}

// ApplyConfigOverrides applies user-defined values from the config file.
func ApplyConfigOverrides(globalMax, defConc, maxConc, defDelay *int, limits, delays map[string]map[string]int) {
	if globalMax != nil {
		GlobalMaxConcurrency = *globalMax
		dispatcherConcurrencyLimit = make(chan struct{}, GlobalMaxConcurrency)
	}
	if defConc != nil {
		DefaultFuncConcurrency = *defConc
	}
	if maxConc != nil {
		MaxAllowedFuncConcurrency = *maxConc
	}
	if defDelay != nil {
		DefaultFuncDelayMs = *defDelay
	}
	cfgFuncLimits = limits
	cfgFuncDelays = delays
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
	funcLimits = make(map[string]map[string]int)
	funcDelays = make(map[string]map[string]int)
	var registrations []schema.ModuleRegistration

	for _, m := range ModuleRegistry {
		caps, err := m.Capabilities()
		if err != nil {
			continue
		}

		funcSet := make(map[string]bool)
		for _, fn := range caps.Functions {
			funcSet[fn] = true
		}
		for fn := range caps.CustomFunctions {
			funcSet[fn] = true
		}

		var mergedFuncs []string
		for fn := range funcSet {
			mergedFuncs = append(mergedFuncs, fn)
		}

		if len(mergedFuncs) == 0 {
			registrations = append(registrations, schema.ModuleRegistration{
				Name:        m.Name(),
				Caps:        schema.ModuleCapabilities{},
				EnabledFunc: enabledConfigs[m.Name()],
			})
			continue
		}

		for _, fn := range mergedFuncs {
			limit := DefaultFuncConcurrency
			delayMs := DefaultFuncDelayMs

			// Cascade: base contract -> module-level config -> per-function config.
			var fnTypes []string
			if len(caps.InputTypes) > 0 {
				fnTypes = caps.InputTypes
			}

			var reqTags [][]string
			var excTags [][]string
			var rawTags [][]string

			if caps.ModuleConfig != nil {
				if caps.ModuleConfig.Limit > 0 {
					limit = caps.ModuleConfig.Limit
				}
				if caps.ModuleConfig.DelayMs >= 0 {
					delayMs = caps.ModuleConfig.DelayMs
				}
				if len(caps.ModuleConfig.InputTypes) > 0 {
					fnTypes = caps.ModuleConfig.InputTypes
				}
				if len(caps.ModuleConfig.RequiredTags) > 0 {
					rawTags = caps.ModuleConfig.RequiredTags
				}
			}

			// Per-function config takes highest priority.
			if custom, exists := caps.CustomFunctions[fn]; exists {
				if custom.Limit > 0 {
					limit = custom.Limit
				}
				if custom.DelayMs >= 0 {
					delayMs = custom.DelayMs
				}
				if len(custom.InputTypes) > 0 {
					fnTypes = custom.InputTypes
				}
				if len(custom.RequiredTags) > 0 {
					rawTags = custom.RequiredTags
				}
			}

			if len(rawTags) > 0 {
				reqTags = make([][]string, 0, len(rawTags))
				excTags = make([][]string, 0, len(rawTags))
				for _, group := range rawTags {
					var reqGroup []string
					var excGroup []string
					for _, tag := range group {
						if len(tag) > 0 && tag[0] == '!' {
							excGroup = append(excGroup, tag[1:])
						} else {
							reqGroup = append(reqGroup, tag)
						}
					}
					reqTags = append(reqTags, reqGroup)
					excTags = append(excTags, excGroup)
				}
			}

			if cfgFuncLimits != nil {
				if modCfg, ok := cfgFuncLimits[m.Name()]; ok {
					if v, ok := modCfg[fn]; ok && v > 0 {
						limit = v
					}
				}
			}
			if cfgFuncDelays != nil {
				if modCfg, ok := cfgFuncDelays[m.Name()]; ok {
					if v, ok := modCfg[fn]; ok && v >= 0 {
						delayMs = v
					}
				}
			}

			if funcLimits[m.Name()] == nil {
				funcLimits[m.Name()] = make(map[string]int)
				funcDelays[m.Name()] = make(map[string]int)
			}
			funcLimits[m.Name()][fn] = limit
			funcDelays[m.Name()][fn] = delayMs

			registrations = append(registrations, schema.ModuleRegistration{
				Name: m.Name(),
				Caps: schema.ModuleCapabilities{
					Functions:  []string{fn},
					InputTypes: fnTypes,
				},
				EnabledFunc: enabledConfigs[m.Name()],
			})

			if !enabledConfigs[m.Name()][fn] {
				continue
			}

			if limit > MaxAllowedFuncConcurrency {
				limit = MaxAllowedFuncConcurrency
			}

			limitKey := fmt.Sprintf("%s|%s", m.Name(), fn)
			moduleLimits.Store(limitKey, &moduleLimit{
				sem:     make(chan struct{}, limit),
				limit:   limit,
				delayMs: delayMs,
			})
			for _, t := range fnTypes {
				moduleIndex[t] = append(moduleIndex[t], moduleEntry{
					mod:         m,
					functions:   []string{fn},
					requireTags: reqTags,
					excludeTags: excTags,
				})
			}
		}
	}

	return repository.SyncMasterDB(ctx, registrations)
}

// Dispatch routes each entity to the appropriate modules based on type and pending functions.
func Dispatch(data *schema.RepoToDispatcherData, out chan<- *schema.ProcessorToRepoData, writersWg *sync.WaitGroup) {
	for _, item := range data.Batch {
		go func(item schema.RepoToDispatcherBatchItem) {
			dispatcherConcurrencyLimit <- struct{}{}
			defer func() { <-dispatcherConcurrencyLimit }()

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
			var resultsMu sync.Mutex
			var entryWg sync.WaitGroup

			for _, entry := range entries {
				entryWg.Add(1)
				go func(entry moduleEntry) {
					defer entryWg.Done()

					if !matchTags(item.Entity.Tags, entry.requireTags, entry.excludeTags) {
						return
					}

					var pending []string
					var flightKeys []string
					for _, fn := range entry.functions {
						modFn := schema.ModuleFunction{ModuleName: entry.mod.Name(), Function: fn}
						if _, done := completedSet[modFn]; !done {
							key := fmt.Sprintf("%s|%s|%s|%s|%s", data.ProjectID, item.Entity.Type, item.Entity.Value, entry.mod.Name(), fn)
							if _, loaded := inFlight.LoadOrStore(key, struct{}{}); !loaded {
								pending = append(pending, fn)
								flightKeys = append(flightKeys, key)
							}
						}
					}

					if len(pending) == 0 {
						return
					}

					caps, err := entry.mod.Capabilities()
					if err != nil {
						for _, k := range flightKeys {
							inFlight.Delete(k)
						}
						return
					}

					var subWg sync.WaitGroup
					for i, fn := range pending {
						subWg.Add(1)
						go func(fn string, flightKey string) {
							defer subWg.Done()

							functionInputTypes := make(map[string][]string)
							var types []string
							if custom, ok := caps.CustomFunctions[fn]; ok && len(custom.InputTypes) > 0 {
								types = custom.InputTypes
							} else if caps.ModuleConfig != nil && len(caps.ModuleConfig.InputTypes) > 0 {
								types = caps.ModuleConfig.InputTypes
							} else {
								types = caps.InputTypes
							}
							functionInputTypes[fn] = types

							safeTags := make([]string, len(item.Entity.Tags))
							copy(safeTags, item.Entity.Tags)

							safeEntity := item.Entity
							safeEntity.Tags = safeTags

							payload := schema.ModuleInput{
								Target:    safeEntity,
								Functions: []string{fn},
							}

							type modResult struct {
								res schema.ModuleOutput
								err error
							}
							resChan := make(chan modResult, 1)

							var modLim *moduleLimit
							limitKey := fmt.Sprintf("%s|%s", entry.mod.Name(), fn)
							if val, ok := moduleLimits.Load(limitKey); ok {
								modLim = val.(*moduleLimit)
								modLim.sem <- struct{}{}
							}

							go func() {
								if modLim != nil {
									if modLim.delayMs > 0 {
										modLim.mu.Lock()
										last := time.Unix(0, atomic.LoadInt64(&modLim.lastRun))
										elapsed := time.Since(last)
										delay := time.Duration(modLim.delayMs) * time.Millisecond
										if elapsed < delay {
											time.Sleep(delay - elapsed)
										}
										atomic.StoreInt64(&modLim.lastRun, time.Now().UnixNano())
										modLim.mu.Unlock()
									}

									defer func() {
										<-modLim.sem
									}()
								}
								res, err := entry.mod.Exec(payload)
								resChan <- modResult{res, err}
							}()

							var result schema.ModuleOutput
							var execErr error
							timedOut := false

							timeout := GetGlobalTimeout()
							timer := time.NewTimer(timeout)
							select {
							case r := <-resChan:
								timer.Stop()
								result = r.res
								execErr = r.err
							case <-timer.C:
								timedOut = true
							}

							go func(keys []string) {
								time.Sleep(5 * time.Second)
								for _, k := range keys {
									inFlight.Delete(k)
								}
							}([]string{flightKey})

							if timedOut {
								var systemErrors []schema.ProcessorInputError
								timeoutMsg := fmt.Sprintf("SYSTEM: Timeout exceeded after %v", timeout)
								systemErrors = append(systemErrors, schema.ProcessorInputError{
									Function: fn,
									Type:     "timeout",
									Text:     timeoutMsg,
								})

								processorData := &schema.ProcessorInputData{
									ProjectID:  data.ProjectID,
									ModuleName: entry.mod.Name(),
									SourceEntity: schema.Entity{
										Type:  item.Entity.Type,
										Value: item.Entity.Value,
									},
									RequestedFunctions: []string{fn},
									FunctionInputTypes: functionInputTypes,
									Errors:             systemErrors,
								}
								resultsMu.Lock()
								moduleResults = append(moduleResults, processorData)
								anyDispatched = true
								resultsMu.Unlock()
								return
							}

							if execErr != nil {
								return
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
								ProjectID:  data.ProjectID,
								ModuleName: entry.mod.Name(),
								SourceEntity: schema.Entity{
									Type:  item.Entity.Type,
									Value: item.Entity.Value,
								},
								Executions:         executions,
								RequestedFunctions: []string{fn},
								FunctionInputTypes: functionInputTypes,
							}

							resultsMu.Lock()
							moduleResults = append(moduleResults, processorData)
							anyDispatched = true
							resultsMu.Unlock()
						}(fn, flightKeys[i])
					}
					subWg.Wait()
				}(entry)
			}
			entryWg.Wait()
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

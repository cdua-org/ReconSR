package controller

import (
	"cdua-org/ReconSR/internal/dispatcher"
	"cdua-org/ReconSR/internal/repository"
	"cdua-org/ReconSR/internal/scopemanager"
	"cdua-org/ReconSR/internal/updater"
	"cdua-org/ReconSR/internal/validator"
	"cdua-org/ReconSR/schema"
	"context"
	"errors"
	"os"
	"slices"
	"sync"
	"time"
)

var (
	activeSession  *schema.PipelineInjection
	currentProjID  string
	syncedProjects = make(map[string]bool)
	syncedMu       sync.Mutex
)

var (
	ErrUnsupportedType = validator.ErrUnsupportedType
	ErrInvalidSyntax   = validator.ErrInvalidSyntax
	ErrOutOfScope      = errors.New("out_of_scope")
	ErrNoModules       = errors.New("no_modules_found")
	ErrNoActiveFuncs   = errors.New("no_active_functions")
)

// GetInjection returns the prepared injection for the pipeline and clears it.
func GetInjection() *schema.PipelineInjection {
	inj := activeSession
	activeSession = nil
	return inj
}

const unlimitedDepth = 999999

// GetActiveGraph retrieves the results for the currently active session and applies depth limits.
func GetActiveGraph(ctx context.Context, includeRawData bool) (*schema.ProjectGraph, error) {
	if currentProjID == "" {
		return nil, errors.New("no active project")
	}

	graph, err := repository.GetGraphData(ctx, currentProjID, includeRawData)
	if err != nil {
		return nil, err
	}

	deleted, err := repository.DeleteTempProject(ctx, currentProjID)
	if err != nil {
		return nil, err
	}
	if deleted {
		ClearActiveProject()
		graph.MaxDepth = unlimitedDepth
		graph.StrictDepth = false
		return graph, nil
	}

	root, err := os.OpenRoot(".")
	if err != nil {
		return nil, err
	}
	defer root.Close()

	_, _, _, _, _, _, _, _, maxDepth, strictDepth, _, _, err := loadConfigFromFile(root)
	if err != nil {
		return nil, err
	}

	graph.MaxDepth = maxDepth
	graph.StrictDepth = strictDepth

	return graph, nil
}

// GetActiveProjectStats retrieves the counts of unique entity values for the active project.
func GetActiveProjectStats(ctx context.Context) (int, map[string]map[string]int, map[string]int, error) {
	if currentProjID == "" {
		return 0, nil, nil, errors.New("no active project")
	}
	stats, err := repository.GetProjectStats(ctx, currentProjID)
	if err != nil {
		return 0, nil, nil, err
	}

	totalEntities := 0
	totalsByCat := make(map[string]int, len(stats))
	for cat, types := range stats {
		for _, count := range types {
			totalsByCat[cat] += count
			totalEntities += count
		}
	}

	return totalEntities, stats, totalsByCat, nil
}

// SetActiveProject explicitly sets the current project identifier.
func SetActiveProject(projectID string) {
	currentProjID = projectID
}

// GetActiveProjectID returns the current project identifier.
func GetActiveProjectID() string {
	return currentProjID
}

// ClearActiveProject resets the current project identifier.
func ClearActiveProject() {
	currentProjID = ""
	activeSession = nil
}

// ValidateTarget checks if the input is valid and returns its type, value.
func ValidateTarget(ctx context.Context, targetType, rawInput string, ignoreScope bool) (string, string, error) {
	res, err := validator.Validate(targetType, rawInput)
	if err != nil {
		return "", "", err
	}

	if ignoreScope {
		return res.Type, res.Value, nil
	}

	if _, err := scopemanager.Load(ctx); err != nil {
		return "", "", err
	}
	if scopemanager.IsOutOfScope(res.Type, res.Value) {
		return "", "", ErrOutOfScope
	}

	return res.Type, res.Value, nil
}

type TargetItem = repository.TargetItem

// GetExistingTargets returns all distinct initial targets from the repository.
func GetExistingTargets(ctx context.Context) ([]TargetItem, error) {
	return repository.GetExistingTargets(ctx)
}

// GetProjects searches for existing projects and checks module support by target.
func GetProjects(ctx context.Context, targetType, targetValue string) ([]schema.ProjectInfo, bool, bool, error) {
	return repository.FindProjects(ctx, targetType, targetValue)
}

// GetProjectStatus analyzes pending tasks and errors for a specific project.
func GetProjectStatus(ctx context.Context, projectID string) ([]string, []string, error) {
	changed, err := scopemanager.Load(ctx)
	if err != nil {
		return nil, nil, err
	}

	syncedMu.Lock()
	if changed {
		syncedProjects = make(map[string]bool)
	}
	needsSync := !syncedProjects[projectID]
	syncedMu.Unlock()

	if needsSync {
		if _, err := SyncScopeWithDB(ctx, projectID); err != nil {
			return nil, nil, err
		}
		syncedMu.Lock()
		syncedProjects[projectID] = true
		syncedMu.Unlock()
	}

	pendingTasks, errorTasks, err := repository.GetProjectStatus(ctx, projectID)
	if err != nil {
		return nil, nil, err
	}

	root, err := os.OpenRoot(".")
	if err != nil {
		return nil, nil, err
	}
	defer root.Close()

	_, _, _, _, _, _, _, _, maxDepth, strictDepth, _, _, err := loadConfigFromFile(root)
	if err != nil {
		return nil, nil, err
	}

	pendingMap := make(map[string]bool)
	for _, task := range pendingTasks {
		currentDepth := task.DepthRelaxed
		if strictDepth {
			currentDepth = task.DepthStrict
		}

		if currentDepth > maxDepth {
			continue
		}

		if dispatcher.IsActionable(task.EntityType, task.ModuleName, task.Function, task.EntityTags) {
			pendingMap[task.ModuleName+":"+task.Function] = true
		}
	}

	errorMap := make(map[string]bool)
	for _, task := range errorTasks {
		currentDepth := task.DepthRelaxed
		if strictDepth {
			currentDepth = task.DepthStrict
		}

		if currentDepth > maxDepth {
			continue
		}

		if dispatcher.IsActionable(task.EntityType, task.ModuleName, task.Function, task.EntityTags) {
			errorMap[task.ModuleName+":"+task.Function] = true
		}
	}

	pending := make([]string, 0, len(pendingMap))
	for p := range pendingMap {
		pending = append(pending, p)
	}

	errs := make([]string, 0, len(errorMap))
	for e := range errorMap {
		errs = append(errs, e)
	}

	return pending, errs, nil
}

// ResetProjectLog clears the execution history to force a rescan.
func ResetProjectLog(ctx context.Context, projectID string, clearAll, clearErrors bool) error {
	return repository.ResetProjectLog(ctx, projectID, clearAll, clearErrors)
}

// CreateNewProject generates a DB and prepares the initial session state.
func CreateNewProject(ctx context.Context, targetType, targetValue string) (string, error) {
	res, err := validator.Validate(targetType, targetValue)
	if err != nil {
		return "", err
	}
	anchor := res.Anchor
	if res.Type == "domain" {
		anchor = ""
	}

	// Double check module availability before final creation
	_, hasModules, hasActiveFuncs, err := repository.FindProjects(ctx, targetType, targetValue)
	if err != nil {
		return "", err
	}
	if !hasModules {
		return "", ErrNoModules
	}
	if !hasActiveFuncs {
		return "", ErrNoActiveFuncs
	}

	routeRef, err := repository.CreateProjectDB(ctx, targetType, targetValue, anchor)
	if err != nil {
		return "", err
	}

	if err := SetResumeSession(ctx, routeRef, true, false); err != nil {
		return "", err
	}

	return routeRef, nil
}

// SetResumeSession prepares the payload for an existing project and sets it as active.
func SetResumeSession(ctx context.Context, projectID string, resumePending, retryErrors bool) error {
	settings := GetModuleSettings()
	if err := dispatcher.LoadConfig(ctx, settings); err != nil {
		return err
	}
	payload, err := repository.GetResumePayload(ctx, projectID, resumePending, retryErrors)
	if err != nil {
		return err
	}
	if payload == nil {
		return errors.New("no pending tasks found for project")
	}
	activeSession = &schema.PipelineInjection{ToDispatcher: payload}
	currentProjID = projectID
	return nil
}

// SystemStatus contains aggregate counts of modules and functions in the system.
type SystemStatus struct {
	TotalModules  int
	ActiveModules int
	TotalFuncs    int
	ActiveFuncs   int
}

// GetSystemStatus returns the current module and function counts from the dispatcher.
func GetSystemStatus() SystemStatus {
	settings := GetModuleSettings()
	allCaps := dispatcher.GetAllCapabilities()

	var status SystemStatus
	status.TotalModules = len(allCaps)
	for _, fns := range allCaps {
		status.TotalFuncs += len(fns)
	}

	for _, fns := range settings {
		hasActive := false
		for _, enabled := range fns {
			if enabled {
				status.ActiveFuncs++
				hasActive = true
			}
		}
		if hasActive {
			status.ActiveModules++
		}
	}
	return status
}

// GetProjectGraph retrieves the complete relationship graph for a project.
func GetProjectGraph(ctx context.Context, projectID string, includeRawData bool) (*schema.ProjectGraph, error) {
	return repository.GetGraphData(ctx, projectID, includeRawData)
}

// GetModuleCount returns the total number of registered modules.
func GetModuleCount() int {
	return len(dispatcher.ModuleRegistry)
}

// PauseRecon pauses the reconnaissance pipeline execution.
func PauseRecon() {
	dispatcher.SetPause(true)
}

// ResumeRecon resumes the paused reconnaissance pipeline execution.
func ResumeRecon() {
	dispatcher.SetPause(false)
}

// DeleteProject removes a project by its identifier.
func DeleteProject(ctx context.Context, projectID string) error {
	if currentProjID == projectID {
		ClearActiveProject()
	}
	syncedMu.Lock()
	delete(syncedProjects, projectID)
	syncedMu.Unlock()
	return repository.DeleteProject(ctx, projectID)
}

// CheckAppUpdate retrieves the latest release information via updater.
func CheckAppUpdate(ctx context.Context) (*updater.ReleaseInfo, error) {
	ctxTimeout, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return updater.FetchLatestRelease(ctxTimeout, nil)
}

// SyncScopeWithDB synchronizes the database entities' scope status with in-memory scope rules.
func SyncScopeWithDB(ctx context.Context, projectID string) (unblockedEntities []schema.EntityRef, err error) {
	allowed, blocked, err := repository.GetScopeAuditEntities(ctx, projectID)
	if err != nil {
		return nil, err
	}

	toNullIDs := make([]int64, 0, len(allowed))
	toOneIDs := make([]int64, 0, len(allowed))
	toZeroIDs := make([]int64, 0, len(blocked))
	unblockedEntities = make([]schema.EntityRef, 0, len(blocked))

	for _, item := range allowed {
		if scopemanager.IsExplicitlyAllowed(item.Type, item.Value) {
			continue
		}
		if scopemanager.IsOutOfScope(item.Type, item.Value) {
			toOneIDs = append(toOneIDs, item.ID)
		} else {
			toNullIDs = append(toNullIDs, item.ID)
		}
	}

	for _, item := range blocked {
		if scopemanager.IsExplicitlyAllowed(item.Type, item.Value) {
			toZeroIDs = append(toZeroIDs, item.ID)
			unblockedEntities = append(unblockedEntities, schema.EntityRef{
				Type:  item.Type,
				Value: item.Value,
			})
		}
	}

	if err = repository.UpdateEntitiesScope(ctx, projectID, toNullIDs, toOneIDs, toZeroIDs); err != nil {
		return nil, err
	}

	return unblockedEntities, nil
}

// CheckAndResumeScope checks for scope changes and sends unblocked entities to the pipeline if available.
func CheckAndResumeScope(ctx context.Context, dispatchChan chan<- *schema.RepoToDispatcherData, writersWg *sync.WaitGroup) bool {
	if ctx.Err() != nil || currentProjID == "" {
		return false
	}

	changed, err := scopemanager.Load(ctx)
	if err != nil {
		return false
	}

	syncedMu.Lock()
	if changed {
		syncedProjects = make(map[string]bool)
	}
	needsSync := !syncedProjects[currentProjID]
	syncedMu.Unlock()

	if !needsSync {
		return false
	}

	unblockedEntities, err := SyncScopeWithDB(ctx, currentProjID)
	if err != nil {
		return false
	}

	syncedMu.Lock()
	syncedProjects[currentProjID] = true
	syncedMu.Unlock()

	if len(unblockedEntities) == 0 {
		return false
	}

	payload, err := repository.GetResumePayload(ctx, currentProjID, true, false)
	if err != nil || payload == nil || len(payload.Batch) == 0 {
		return false
	}

	tokens := len(payload.Batch)
	writersWg.Add(tokens)
	select {
	case <-ctx.Done():
		writersWg.Add(-tokens)
		return false
	case dispatchChan <- payload:
		return true
	}
}

// CleanupTempDatabases delegates orphaned temporary database cleanup to the repository.
func CleanupTempDatabases(ctx context.Context) error {
	return repository.CleanupOrphanedTempDatabases(ctx)
}

// GetAvailableModules retrieves registered module capabilities from the repository.
func GetAvailableModules(ctx context.Context) (map[string]map[string][]string, error) {
	return repository.GetAvailableModules(ctx)
}

// ModuleValidationResult groups the categorization of requested modules and functions.
type ModuleValidationResult struct {
	Supported         map[string][]string
	NotFoundModules   []string
	NotFoundFuncs     map[string][]string
	IncompatibleFuncs map[string][]string
}

// ValidateModuleFunctions validates requested module specs against available modules and target type.
func ValidateModuleFunctions(ctx context.Context, targetType string, requested map[string][]string) (*ModuleValidationResult, error) {
	avail, err := repository.GetAvailableModules(ctx)
	if err != nil {
		return nil, err
	}

	res := &ModuleValidationResult{
		Supported:         make(map[string][]string, len(requested)),
		NotFoundFuncs:     make(map[string][]string),
		IncompatibleFuncs: make(map[string][]string),
	}

	for modName, explicitFuncs := range requested {
		availFuncs, exists := avail[modName]
		if !exists {
			res.NotFoundModules = append(res.NotFoundModules, modName)
			continue
		}

		funcsToCheck := explicitFuncs
		if len(funcsToCheck) == 0 {
			funcsToCheck = make([]string, 0, len(availFuncs))
			for fn := range availFuncs {
				funcsToCheck = append(funcsToCheck, fn)
			}
		}

		for _, fn := range funcsToCheck {
			types, fnExists := availFuncs[fn]
			if !fnExists {
				res.NotFoundFuncs[modName] = append(res.NotFoundFuncs[modName], fn)
				continue
			}

			if slices.Contains(types, targetType) {
				res.Supported[modName] = append(res.Supported[modName], fn)
			} else {
				res.IncompatibleFuncs[modName] = append(res.IncompatibleFuncs[modName], fn)
			}
		}
	}

	return res, nil
}

// PrepareStandaloneSession prepares the standalone execution pipeline and returns the temporary project ID.
func PrepareStandaloneSession(ctx context.Context, targetType, targetValue string, ignoreScope bool, supported map[string][]string) (string, error) {
	res, err := validator.Validate(targetType, targetValue)
	if err != nil {
		return "", err
	}
	anchor := res.Anchor
	if res.Type == "domain" {
		anchor = ""
	}

	if !ignoreScope {
		if _, err := scopemanager.Load(ctx); err != nil {
			return "", err
		}
		if scopemanager.IsOutOfScope(res.Type, res.Value) {
			return "", ErrOutOfScope
		}
	}

	baseSettings := GetModuleSettings()
	standaloneSettings := make(map[string]map[string]bool, len(baseSettings))
	for mod, fns := range baseSettings {
		standaloneSettings[mod] = make(map[string]bool, len(fns))
		for fn := range fns {
			standaloneSettings[mod][fn] = false
		}
	}
	for mod, fns := range supported {
		if standaloneSettings[mod] == nil {
			standaloneSettings[mod] = make(map[string]bool, len(fns))
		}
		for _, fn := range fns {
			standaloneSettings[mod][fn] = true
		}
	}

	dispatcher.LoadMemoryConfig(standaloneSettings)

	routeRef, err := repository.CreateTempProjectDB(ctx, res.Type, res.Value, anchor)
	if err != nil {
		return "", err
	}

	payload, err := repository.GetResumePayload(ctx, routeRef, true, false)
	if err == nil && (payload == nil || len(payload.Batch) == 0) {
		err = errors.New("no pending tasks found for project")
	}
	if err != nil {
		if _, delErr := repository.DeleteTempProject(ctx, routeRef); delErr != nil {
			return "", delErr
		}
		return "", err
	}

	activeSession = &schema.PipelineInjection{ToDispatcher: payload}
	currentProjID = routeRef

	return routeRef, nil
}
